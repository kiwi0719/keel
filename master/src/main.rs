//! keel-master: the web panel, its SQLite store, subscription links and the
//! control channel keel-node instances dial into. One process, one port.
//!
//!   keel-master -data /var/lib/keel-master -listen 0.0.0.0:8443

mod api;
mod app;
mod db;
mod dns;
mod link;
mod live;
mod nodecfg;
mod panel_cert;
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

type TlsSetup = (Arc<rustls::ServerConfig>, TlsInfo, Option<panel_cert::PanelTls>);

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
                // Nothing in it names keel. Nodes pin this certificate, so it
                // is long-lived: replacing it means reinstalling every node.
                let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
                let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(|e| e.to_string())?;
                params.distinguished_name = rcgen::DistinguishedName::new();
                params.distinguished_name.push(rcgen::DnType::CommonName, "localhost");
                let year = 1970 + (period::now() / 31_556_952) as i32;
                params.not_before = rcgen::date_time_ymd(year, 1, 1);
                params.not_after = rcgen::date_time_ymd(year + 20, 1, 1);
                let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
                write_private(&k, key.serialize_pem().as_bytes())?;
                std::fs::write(&c, cert.pem()).map_err(|e| e.to_string())?;
                eprintln!("generated a self-signed certificate in {}", dir.display());
            }
            (std::fs::read(&c).map_err(|e| e.to_string())?, std::fs::read(&k).map_err(|e| e.to_string())?, true)
        }
    };
    let certs: Vec<_> = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    let leaf = certs.first().ok_or("no certificate in the cert file")?;
    let cert_sha256 = util::hex(&util::sha256(leaf.as_ref()));
    let key = rustls_pemfile::private_key(&mut &key_pem[..]).map_err(|e| e.to_string())?.ok_or("no private key in the key file")?;
    let spki = util::sha256(&leaf_spki(leaf.as_ref()).ok_or("cannot read the certificate's public key")?);
    let spki_sha256 = util::hex(&spki);
    let spki_pin = if self_signed {
        use base64::Engine;
        Some(base64::engine::general_purpose::STANDARD.encode(spki))
    } else {
        None
    };
    let _ = key;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth();
    // Served through a resolver so the panel certificate can be replaced
    // (panel_cert) without a restart.
    let resolver = Arc::new(panel_cert::Resolver::new(panel_cert::certified(&cert_pem, &key_pem)?));
    let mut config = config.with_cert_resolver(resolver.clone());
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let panel = self_signed.then(|| panel_cert::PanelTls {
        resolver,
        dir: o.data.join("tls"),
        key_pem: String::from_utf8_lossy(&key_pem).into_owned(),
    });
    Ok((Arc::new(config), TlsInfo { cert_sha256, spki_sha256, spki_pin }, panel))
}

/// The DER SubjectPublicKeyInfo of a certificate: the third element of the
/// TBSCertificate after the optional version, serial, signature, issuer and
/// validity, i.e. element 6 (with version) of the TBS sequence.
fn leaf_spki(der: &[u8]) -> Option<Vec<u8>> {
    // (tag, header length, content length) of the element at the start of b
    fn elem(b: &[u8]) -> Option<(u8, usize, usize)> {
        let tag = *b.first()?;
        let first = *b.get(1)? as usize;
        if first < 0x80 {
            return Some((tag, 2, first));
        }
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        Some((tag, 2 + n, len))
    }
    let (_, h, _) = elem(der)?; // Certificate
    let tbs = der.get(h..)?;
    let (_, th, tlen) = elem(tbs)?; // TBSCertificate
    let mut b = tbs.get(th..th + tlen)?;
    let mut index = 0;
    loop {
        let (tag, eh, elen) = elem(b)?;
        let whole = b.get(..eh + elen)?;
        // version [0] is optional: skip it without counting
        if !(index == 0 && tag == 0xa0) {
            index += 1;
            if index == 6 {
                return Some(whole.to_vec());
            }
        }
        b = b.get(eh + elen..)?;
    }
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

/// The data directory holds every secret (node tokens, user keys, the
/// Cloudflare token, sessions): owner only. SQLite gives its -wal and -shm
/// files the database file's mode.
fn lock_down(data: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let set = |p: &Path, mode: u32| {
            if p.exists() {
                if let Err(e) = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)) {
                    eprintln!("{}: {e}", p.display());
                }
            }
        };
        set(data, 0o700);
        let db = data.join("keel.db");
        if !db.exists() {
            let _ = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&db);
        }
        for name in ["keel.db", "keel.db-wal", "keel.db-shm"] {
            set(&data.join(name), 0o600);
        }
    }
}

fn static_file(body: &'static str, ctype: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ctype), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

async fn install_script() -> Response {
    static_file(INSTALL_SH, "text/x-shellscript; charset=utf-8")
}

/// What a node listens on, for install.sh to print: one line per port,
/// "<what> <listen port> <public port>". Authenticated by the node token.
async fn node_ports(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let token = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("").trim();
    let node = if token.is_empty() { None } else { db::node_by_token(&app.reader(), token).ok().flatten() };
    let Some(n) = node else {
        tokio::time::sleep(Duration::from_secs(1)).await;
        return (StatusCode::UNAUTHORIZED, "bad token\n").into_response();
    };
    let mut out = String::new();
    let pick = |p: i64, pub_: i64| if pub_ > 0 { pub_ } else { p };
    if n.is_entry() {
        if n.anytls_on && n.anytls_port > 0 {
            out.push_str(&format!("AnyTLS {} {}\n", n.anytls_port, pick(n.anytls_port, n.anytls_pub)));
        }
        if n.vless_on && n.vless_port > 0 {
            out.push_str(&format!("VLESS-Reality {} {}\n", n.vless_port, pick(n.vless_port, n.vless_pub)));
        }
    } else if let Ok(exits) = db::exits_of(&app.reader(), n.id) {
        for e in &exits {
            out.push_str(&format!("SS-2022({}) {} {}\n", e.name.replace(' ', "_"), e.port, e.public_port()));
        }
    }
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], out).into_response()
}

/// Node binaries placed in DIR/dist, e.g. keel-node-linux-amd64. Streamed
/// from the file in 64 KiB pieces, so neither a slow download nor the master
/// between downloads holds a copy of the binary.
async fn download(State(app): State<Arc<App>>, UrlPath(name): UrlPath<String>) -> Response {
    use tokio::io::AsyncReadExt;
    let valid = name.starts_with("keel-node-") && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
    if !valid {
        return StatusCode::NOT_FOUND.into_response();
    }
    let missing = || (StatusCode::NOT_FOUND, format!("{name} is not in the master's dist directory\n")).into_response();
    let Ok(file) = tokio::fs::File::open(app.dist.join(&name)).await else { return missing() };
    // The length of the file opened, even if the name is replaced meanwhile.
    let Ok(meta) = file.metadata().await else { return missing() };
    if !meta.is_file() {
        return missing();
    }
    let chunks = futures_util::stream::unfold(Some(file), |file| async move {
        let mut file = file?;
        let mut chunk = vec![0u8; 64 << 10];
        match file.read(&mut chunk).await {
            Ok(0) => None,
            Ok(n) => {
                chunk.truncate(n);
                Some((Ok(bytes::Bytes::from(chunk)), Some(file)))
            }
            Err(e) => Some((Err(e), None)),
        }
    });
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream")), (header::CONTENT_LENGTH, HeaderValue::from(meta.len()))],
        axum::body::Body::from_stream(chunks),
    )
        .into_response()
}

async fn security_headers(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    // API answers and subscriptions carry secrets: never keep them in caches.
    let private = req.uri().path().starts_with("/api/") || req.uri().path().starts_with("/s/");
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if private {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("x-robots-tag", HeaderValue::from_static("noindex, nofollow, noarchive"));
    h.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
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
        .route("/api/users/per-entry", post(api::users_per_entry))
        .route("/api/settings", patch(api::update_settings))
        .route("/api/logout", post(api::logout))
        .route_layer(axum::middleware::from_fn_with_state(app.clone(), api::require_login));
    Router::new()
        .route("/", get(|State(app): State<Arc<App>>| async move {
            // The public probe page is opt-in: off, the root answers like an
            // empty server and says nothing about what runs here.
            if api::public_page(&app) {
                static_file(INDEX_HTML, "text/html; charset=utf-8")
            } else {
                StatusCode::NOT_FOUND.into_response()
            }
        }))
        .route("/admin", get(|| async { static_file(INDEX_HTML, "text/html; charset=utf-8") }))
        .route("/api/public", get(api::public_state))
        .route("/robots.txt", get(|| async { static_file("User-agent: *\nDisallow: /\n", "text/plain; charset=utf-8") }))
        .route("/app.js", get(|| async { static_file(APP_JS, "text/javascript; charset=utf-8") }))
        .route("/app.css", get(|| async { static_file(APP_CSS, "text/css; charset=utf-8") }))
        .route("/install.sh", get(install_script))
        .route("/dl/{name}", get(download))
        .route("/s/{token}", get(sub::subscription))
        .route("/api/login", post(api::login).layer(axum::extract::DefaultBodyLimit::max(4096)))
        .route("/api/session", get(|State(app): State<Arc<App>>, h: HeaderMap| async move {
            axum::Json(serde_json::json!({"logged_in": api::logged_in(&app, &h).await}))
        }))
        .route("/api/node/ws", get(ws::handler))
        .route("/api/node/ports", get(node_ports))
        .merge(private)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(app)
}

/// Connections served at once, and from one address. Each costs a file
/// descriptor; without caps idle sockets alone could use up the process limit.
const MAX_CONNS: usize = 512;
const MAX_CONNS_PER_IP: usize = 32;
/// A request's headers must arrive within this, also between keep-alive requests.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

static PER_IP: Mutex<Option<std::collections::HashMap<std::net::IpAddr, usize>>> = Mutex::new(None);

/// Holds one per-address connection slot until dropped.
struct IpSlot(std::net::IpAddr);

impl IpSlot {
    fn take(ip: std::net::IpAddr) -> Option<IpSlot> {
        let mut m = PER_IP.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.get_or_insert_with(Default::default).entry(ip).or_insert(0);
        if *n >= MAX_CONNS_PER_IP {
            return None;
        }
        *n += 1;
        Some(IpSlot(ip))
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut m = PER_IP.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(m) = m.as_mut() {
            if let Some(n) = m.get_mut(&self.0) {
                *n -= 1;
                if *n == 0 {
                    m.remove(&self.0);
                }
            }
        }
    }
}

/// Accepts connections for both modes. Behind -no-tls every connection comes
/// from the reverse proxy, so only the global cap applies there.
async fn serve(listener: tokio::net::TcpListener, tls: Option<Arc<rustls::ServerConfig>>, router: Router) {
    let acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNS));
    loop {
        let permit = slots.clone().acquire_owned().await.expect("semaphore never closes");
        let (tcp, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let ip_slot = if acceptor.is_some() {
            match IpSlot::take(peer.ip()) {
                Some(s) => Some(s),
                None => continue,
            }
        } else {
            None
        };
        let acceptor = acceptor.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let _held = (permit, ip_slot);
            match acceptor {
                Some(a) => {
                    let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), a.accept(tcp)).await else { return };
                    serve_conn(tls, peer, router).await
                }
                None => serve_conn(tcp, peer, router).await,
            }
        });
    }
}

async fn serve_conn<S>(io: S, peer: SocketAddr, router: Router)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(ConnectInfo(peer));
        router.clone().oneshot(req)
    });
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(hyper_util::rt::TokioIo::new(io), service)
        .with_upgrades()
        .await;
}

#[tokio::main]
async fn main() {
    let o = parse_args();
    if let Err(e) = std::fs::create_dir_all(&o.data) {
        eprintln!("{}: {e}", o.data.display());
        std::process::exit(1);
    }
    lock_down(&o.data);
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
        // Not in the log, which other accounts may be able to read.
        let path = o.data.join("initial-password");
        match write_private(&path, format!("{} / {pw}\n", api::admin_user(&conn)).as_bytes()) {
            Ok(()) => eprintln!("first start: the panel login is in {} (delete it after changing the password)", path.display()),
            Err(e) => eprintln!("first start: could not save the panel login: {e}; set one with -user and -password -"),
        }
    }
    let secret = match db::get_setting(&conn, "secret").ok().flatten() {
        Some(s) => s,
        None => {
            let s = util::random_hex(32);
            db::set_setting(&conn, "secret", &s).expect("save secret");
            s
        }
    };

    let (tls_config, tls_info, panel_tls) = if o.no_tls {
        (None, None, None)
    } else {
        match load_tls(&o) {
            Ok((config, info, panel)) => {
                // With a self-signed certificate the admin should compare this
                // with what the browser shows before logging in.
                eprintln!("certificate SHA-256 (check it in the browser before logging in): {}", info.cert_sha256);
                eprintln!("public key SHA-256 (keel-node -fingerprint): {}", info.spki_sha256);
                (Some(config), Some(info), panel)
            }
            Err(e) => {
                eprintln!("tls: {e}");
                std::process::exit(1);
            }
        }
    };
    let dist = o.data.join("dist");
    let _ = std::fs::create_dir_all(&dist);
    let reader = db::open_reader(&o.data.join("keel.db")).unwrap_or_else(|e| {
        eprintln!("database: {e}");
        std::process::exit(1)
    });
    let app = Arc::new(App {
        db: Mutex::new(conn),
        db_read: Mutex::new(reader),
        live: Mutex::new(live::Live::default()),
        secret,
        tls: tls_info,
        dist,
        trust_proxy: o.no_tls,
        panel_tls,
    });
    panel_cert::spawn(app.clone());

    {
        let app = app.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            // After a stall, carry on from now instead of catching up.
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
        serve(listener, tls_config, router).await
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
