//! keel-master: the web panel, its SQLite store, subscription links and the
//! control channel keel-node instances dial into. One process, one port.
//!
//!   keel-master -data /var/lib/keel-master -listen 0.0.0.0:8443

mod api;
mod app;
mod db;
mod link;
mod live;
mod nodecfg;
mod period;
mod sub;
mod util;
mod ws;

use axum::extract::{ConnectInfo, Path as UrlPath, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::Router;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower::ServiceExt;

use app::{App, TlsInfo};

const INDEX_HTML: &str = include_str!("../web/index.html");
const APP_JS: &str = include_str!("../web/app.js");
const APP_CSS: &str = include_str!("../web/app.css");
const INSTALL_SH: &str = include_str!("../install.sh");

struct Options {
    data: PathBuf,
    listen: String,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
    no_tls: bool,
    password: Option<String>,
    user: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: keel-master [-data DIR] [-listen ADDR] [-cert FILE -key FILE | -no-tls] [-user NAME] [-password NEW]\n\
         \n  -data DIR      database, generated certificate and node binaries (default /var/lib/keel-master)\
         \n  -listen ADDR   panel, subscriptions and node connections (default 0.0.0.0:8443)\
         \n  -cert, -key    TLS certificate; without them a self-signed one is made in DIR/tls\
         \n  -no-tls        plain HTTP behind a TLS reverse proxy (trusts X-Forwarded-For)\
         \n  -user NAME     set the panel login name and exit (with -password: both)\
         \n  -password NEW  set the panel password and exit (\"-\" reads it from stdin)"
    );
    std::process::exit(2)
}

fn parse_args() -> Options {
    let mut o = Options {
        data: PathBuf::from("/var/lib/keel-master"),
        listen: "0.0.0.0:8443".into(),
        cert: None,
        key: None,
        no_tls: false,
        password: None,
        user: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let flag = a.trim_start_matches('-');
        let mut value = || args.next().unwrap_or_else(|| usage());
        match flag {
            "data" => o.data = value().into(),
            "listen" => o.listen = value(),
            "cert" => o.cert = Some(value().into()),
            "key" => o.key = Some(value().into()),
            "no-tls" => o.no_tls = true,
            "password" => o.password = Some(value()),
            "user" => o.user = Some(value()),
            _ => usage(),
        }
    }
    if o.cert.is_some() != o.key.is_some() {
        usage();
    }
    o
}

type TlsSetup = (Arc<rustls::ServerConfig>, TlsInfo);

fn load_tls(o: &Options) -> Result<TlsSetup, String> {
    let (cert_pem, key_pem, self_signed) = match (&o.cert, &o.key) {
        (Some(c), Some(k)) => (
            std::fs::read(c).map_err(|e| format!("{}: {e}", c.display()))?,
            std::fs::read(k).map_err(|e| format!("{}: {e}", k.display()))?,
            false,
        ),
        _ => {
            let dir = o.data.join("tls");
            let (c, k) = (dir.join("cert.pem"), dir.join("key.pem"));
            if !c.exists() || !k.exists() {
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let cert = rcgen::generate_simple_self_signed(vec!["keel-master".to_string()]).map_err(|e| e.to_string())?;
                write_private(&k, cert.key_pair.serialize_pem().as_bytes())?;
                std::fs::write(&c, cert.cert.pem()).map_err(|e| e.to_string())?;
                eprintln!("generated a self-signed certificate in {}", dir.display());
            }
            (std::fs::read(&c).map_err(|e| e.to_string())?, std::fs::read(&k).map_err(|e| e.to_string())?, true)
        }
    };
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    let leaf = certs.first().ok_or("no certificate in the cert file")?;
    let cert_sha256 = util::hex(&util::sha256(leaf.as_ref()));
    let key = rustls_pemfile::private_key(&mut &key_pem[..]).map_err(|e| e.to_string())?.ok_or("no private key in the key file")?;
    let spki_pin = if self_signed {
        let pem = String::from_utf8_lossy(&key_pem);
        let kp = rcgen::KeyPair::from_pem(&pem).map_err(|e| e.to_string())?;
        use base64::Engine;
        Some(base64::engine::general_purpose::STANDARD.encode(util::sha256(&kp.public_key_der())))
    } else {
        None
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok((Arc::new(config), TlsInfo { cert_sha256, spki_pin }))
}

fn write_private(path: &Path, content: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(content).map_err(|e| e.to_string())
}

fn static_file(body: &'static str, ctype: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ctype), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

async fn install_script() -> Response {
    static_file(INSTALL_SH, "text/x-shellscript; charset=utf-8")
}

/// Node binaries placed in DIR/dist, e.g. keel-node-linux-amd64.
async fn download(State(app): State<Arc<App>>, UrlPath(name): UrlPath<String>) -> Response {
    let valid = name.starts_with("keel-node-") && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
    if !valid {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read(app.dist.join(&name)).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, format!("{name} is not in the master's dist directory\n")).into_response(),
    }
}

async fn security_headers(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("x-robots-tag", HeaderValue::from_static("noindex, nofollow, noarchive"));
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'",
        ),
    );
    resp
}

fn router(app: Arc<App>) -> Router {
    let private = Router::new()
        .route("/api/state", get(api::state))
        .route("/api/nodes", post(api::create_node))
        .route("/api/nodes/{id}", patch(api::update_node).delete(api::delete_node))
        .route("/api/nodes/{id}/rules", put(api::set_rules))
        .route("/api/nodes/{id}/token", post(api::rotate_token))
        .route("/api/nodes/{id}/install", get(api::install_of))
        .route("/api/exits", post(api::create_exit))
        .route("/api/exits/{id}", patch(api::update_exit).delete(api::delete_exit))
        .route("/api/users", post(api::create_user))
        .route("/api/users/{id}", patch(api::update_user).delete(api::delete_user))
        .route("/api/users/{id}/reset", post(api::reset_user))
        .route("/api/users/{id}/sub", post(api::rotate_sub))
        .route("/api/settings", patch(api::update_settings))
        .route("/api/logout", post(api::logout))
        .route_layer(axum::middleware::from_fn_with_state(app.clone(), api::require_login));
    Router::new()
        .route("/", get(|| async { static_file(INDEX_HTML, "text/html; charset=utf-8") }))
        .route("/robots.txt", get(|| async { static_file("User-agent: *\nDisallow: /\n", "text/plain; charset=utf-8") }))
        .route("/app.js", get(|| async { static_file(APP_JS, "text/javascript; charset=utf-8") }))
        .route("/app.css", get(|| async { static_file(APP_CSS, "text/css; charset=utf-8") }))
        .route("/install.sh", get(install_script))
        .route("/dl/{name}", get(download))
        .route("/s/{token}", get(sub::subscription))
        .route("/api/login", post(api::login))
        .route("/api/session", get(|State(app): State<Arc<App>>, h: HeaderMap| async move {
            axum::Json(serde_json::json!({"logged_in": api::logged_in(&app, &h)}))
        }))
        .route("/api/node/ws", get(ws::handler))
        .merge(private)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(app)
}

async fn serve_tls(listener: tokio::net::TcpListener, config: Arc<rustls::ServerConfig>, router: Router) {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await else { return };
            let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                req.extensions_mut().insert(ConnectInfo(peer));
                router.clone().oneshot(req)
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                .with_upgrades()
                .await;
        });
    }
}

#[tokio::main]
async fn main() {
    let o = parse_args();
    if let Err(e) = std::fs::create_dir_all(&o.data) {
        eprintln!("{}: {e}", o.data.display());
        std::process::exit(1);
    }
    let conn = db::open(&o.data.join("keel.db")).unwrap_or_else(|e| {
        eprintln!("database: {e}");
        std::process::exit(1)
    });

    if o.user.is_some() || o.password.is_some() {
        if let Some(user) = &o.user {
            let user = user.trim();
            if user.is_empty() || user.chars().count() > 40 {
                eprintln!("user name must be 1-40 characters");
                std::process::exit(2);
            }
            db::set_setting(&conn, "admin_user", user).expect("save user");
            eprintln!("panel user name set to {user}");
        }
        if let Some(pw) = &o.password {
            // "-" reads it from stdin so it stays out of shell history.
            let pw = if pw == "-" {
                eprint!("new panel password: ");
                let mut line = String::new();
                let _ = std::io::stdin().read_line(&mut line);
                line.trim_end_matches(['\r', '\n']).to_string()
            } else {
                pw.clone()
            };
            if pw.chars().count() < 8 {
                eprintln!("password must be at least 8 characters");
                std::process::exit(2);
            }
            db::set_setting(&conn, "admin_hash", &api::hash_password(&pw)).expect("save password");
            eprintln!("panel password updated");
        }
        let _ = conn.execute("DELETE FROM sessions", []);
        return;
    }
    if db::get_setting(&conn, "admin_hash").ok().flatten().is_none() {
        let pw = util::random_hex(8);
        db::set_setting(&conn, "admin_hash", &api::hash_password(&pw)).expect("save password");
        eprintln!("first start: panel login is {} / {pw} (change it in the panel, or with -user and -password)", api::admin_user(&conn));
    }
    let secret = match db::get_setting(&conn, "secret").ok().flatten() {
        Some(s) => s,
        None => {
            let s = util::random_hex(32);
            db::set_setting(&conn, "secret", &s).expect("save secret");
            s
        }
    };

    let (tls_config, tls_info) = if o.no_tls {
        (None, None)
    } else {
        match load_tls(&o) {
            Ok((config, info)) => {
                eprintln!("certificate SHA-256 (keel-node -fingerprint): {}", info.cert_sha256);
                (Some(config), Some(info))
            }
            Err(e) => {
                eprintln!("tls: {e}");
                std::process::exit(1);
            }
        }
    };
    let dist = o.data.join("dist");
    let _ = std::fs::create_dir_all(&dist);
    let app = Arc::new(App {
        db: Mutex::new(conn),
        live: Mutex::new(live::Live::default()),
        secret,
        tls: tls_info,
        dist,
        trust_proxy: o.no_tls,
    });

    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            let mut n: u64 = 0;
            loop {
                tick.tick().await;
                app.live().sample_speed();
                n += 1;
                if n % 6 == 0 {
                    app.sync();
                }
                if n % 17_280 == 1 {
                    let _ = db::prune(&app.db(), period::now());
                }
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&o.listen).await.unwrap_or_else(|e| {
        eprintln!("listen {}: {e}", o.listen);
        std::process::exit(1)
    });
    eprintln!("keel-master listening on {} ({})", o.listen, if tls_config.is_some() { "https" } else { "http" });
    let router = router(app);
    let server = async move {
        match tls_config {
            Some(config) => serve_tls(listener, config, router).await,
            None => {
                let _ = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await;
            }
        }
    };
    tokio::select! {
        _ = server => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate() => {}
    }
    eprintln!("keel-master stopped");
}

#[cfg(unix)]
async fn terminate() {
    if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        s.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn terminate() {
    std::future::pending::<()>().await
}
