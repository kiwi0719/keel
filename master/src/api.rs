//! Panel JSON API. Every edit ends with App::sync, which pushes the changed
//! node configs right away.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::app::App;
use crate::db;
use crate::link;
use crate::nodecfg::{self, ProbeTarget};
use crate::period::{format_date_end, month_label, now, parse_date_end, period_end};
use crate::util::{random_b64, random_hex};

pub type ApiResult = Result<Response, Response>;

fn bad(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg.into()}))).into_response()
}

fn internal(e: impl std::fmt::Display) -> Response {
    eprintln!("api: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "内部错误"}))).into_response()
}

fn ok(v: Value) -> ApiResult {
    Ok(Json(v).into_response())
}

// __Host-: only this exact origin can set it, so a sibling subdomain cannot
// plant a session cookie that shadows the admin's.
const SESSION_COOKIE: &str = "__Host-keel_session";
/// Marks a browser that has logged in before; it may still log in while the
/// global failure limit is hit, so a flood cannot lock the admin out.
const DEVICE_COOKIE: &str = "__Host-keel_device";
const SESSION_DAYS: i64 = 30;

// ---------- auth ----------

pub fn hash_password(pw: &str) -> String {
    let salt = SaltString::encode_b64(&crate::util::random_bytes(16)).expect("salt");
    Argon2::default().hash_password(pw.as_bytes(), &salt).expect("hash").to_string()
}

fn password_matches(stored: &str, pw: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else { return false };
    Argon2::default().verify_password(pw.as_bytes(), &parsed).is_ok()
}

/// The last `n` characters, for showing which secret is set.
fn tail(s: &str, n: usize) -> String {
    let skip = s.chars().count().saturating_sub(n);
    s.chars().skip(skip).collect()
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|c| {
        let (k, v) = c.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

/// The session as stored: a hash of the cookie, so a copy of the database
/// does not hand out live sessions.
fn session_token(headers: &HeaderMap) -> Option<String> {
    cookie(headers, SESSION_COOKIE).map(|t| session_key(&t))
}

fn session_key(token: &str) -> String {
    crate::util::hex(&crate::util::sha256(token.as_bytes()))
}

fn device_value(app: &App) -> String {
    crate::util::hex(&crate::util::sha256(format!("device:{}", app.secret).as_bytes()))
}

pub fn logged_in(app: &App, headers: &HeaderMap) -> bool {
    let Some(token) = session_token(headers) else { return false };
    let conn = app.db();
    conn.query_row("SELECT 1 FROM sessions WHERE token=?1 AND expires>?2", params![token, now()], |_| Ok(()))
        .is_ok()
}

pub async fn require_login(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    // Changes need a header a form or a cross-site fetch cannot send without
    // a CORS preflight (which the master never answers). SameSite alone
    // still lets same-site pages, e.g. on a node's AnyTLS name, post here.
    let safe = matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD);
    if !safe && req.headers().get("x-keel").is_none_or(|v| v != "1") {
        return (StatusCode::FORBIDDEN, Json(json!({"error": "请求来源不对"}))).into_response();
    }
    if logged_in(&app, req.headers()) {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({"error": "请先登录"}))).into_response()
    }
}

#[derive(Deserialize)]
pub struct Login {
    #[serde(default)]
    username: String,
    password: String,
}

/// The panel login name; "admin" until set with -user or in the settings.
pub fn admin_user(conn: &Connection) -> String {
    db::get_setting(conn, "admin_user").ok().flatten().filter(|u| !u.is_empty()).unwrap_or_else(|| "admin".into())
}

/// Failed logins per client IP: (count, window start). Ten misses in ten
/// minutes lock that IP out until the window passes. GLOBAL counts misses
/// from everywhere: client IPs come from X-Forwarded-For behind a proxy, and
/// anything that reaches the master's port directly (another proxy on the
/// same box) can make that header up.
static FAILS: Mutex<Option<HashMap<String, (u32, i64)>>> = Mutex::new(None);
const FAIL_LIMIT: u32 = 10;
const GLOBAL: &str = "*";
const GLOBAL_FAIL_LIMIT: u32 = 100;
const FAIL_WINDOW: i64 = 600;

/// Argon2 takes ~19 MB and tens of milliseconds per check; a flood of
/// logins waits here instead of exhausting the box.
static VERIFYING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// Whether logins from ip are refused. The global limit does not apply to a
/// browser that logged in before (known_device).
fn locked_out(ip: &str, known_device: bool) -> bool {
    let t = now();
    let mut f = FAILS.lock().unwrap_or_else(|e| e.into_inner());
    let map = f.get_or_insert_with(HashMap::new);
    map.retain(|_, (_, start)| t - *start < FAIL_WINDOW);
    map.get(ip).is_some_and(|(n, _)| *n >= FAIL_LIMIT) || (!known_device && map.get(GLOBAL).is_some_and(|(n, _)| *n >= GLOBAL_FAIL_LIMIT))
}

/// The key failures are counted under: the address, or for IPv6 its /64,
/// which one subscriber line usually has whole.
fn fail_key(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        _ => ip.to_string(),
    }
}

fn record_failure(ip: &str) {
    let t = now();
    let mut f = FAILS.lock().unwrap_or_else(|e| e.into_inner());
    let map = f.get_or_insert_with(HashMap::new);
    for key in [ip, GLOBAL] {
        map.entry(key.to_string()).or_insert((0, t)).0 += 1;
    }
}

pub async fn login(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> ApiResult {
    let ip = fail_key(&crate::ws::client_ip(&app, &headers, peer));
    let known_device = cookie(&headers, DEVICE_COOKIE).is_some_and(|v| v == device_value(&app));
    let too_many = || (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "试错太多次，10 分钟后再试"}))).into_response();
    if locked_out(&ip, known_device) {
        return Err(too_many());
    }
    let (stored, user) = {
        let conn = app.db();
        (db::get_setting(&conn, "admin_hash").ok().flatten(), admin_user(&conn))
    };
    let good = {
        let _permit = VERIFYING.acquire().await.map_err(internal)?;
        // Requests that queued up behind the permit count against the limit too.
        if locked_out(&ip, known_device) {
            return Err(too_many());
        }
        let password = body.password;
        // Check the password even for a wrong name so both take as long.
        let pw_ok = tokio::task::spawn_blocking(move || stored.is_some_and(|h| password_matches(&h, &password)))
            .await
            .unwrap_or(false);
        pw_ok && body.username.trim() == user
    };
    if !good {
        record_failure(&ip);
        tokio::time::sleep(Duration::from_secs(1)).await;
        return Err((StatusCode::UNAUTHORIZED, Json(json!({"error": "用户名或密码不对"}))).into_response());
    }
    let token = random_hex(24);
    app.db()
        .execute("INSERT INTO sessions(token,expires) VALUES(?1,?2)", params![session_key(&token), now() + SESSION_DAYS * 86_400])
        .map_err(internal)?;
    // Behind -no-tls the reverse proxy terminates HTTPS, so the cookie is still secure-only.
    let secure = if app.tls.is_some() || app.trust_proxy { "; Secure" } else { "" };
    let session = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}",
        SESSION_DAYS * 86_400
    );
    let device = format!("{DEVICE_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{secure}", device_value(&app), 400 * 86_400);
    let cookies = axum::response::AppendHeaders([(header::SET_COOKIE, session), (header::SET_COOKIE, device)]);
    Ok((cookies, Json(json!({"ok": true}))).into_response())
}

pub async fn logout(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    if let Some(token) = session_token(&headers) {
        let _ = app.db().execute("DELETE FROM sessions WHERE token=?1", [token]);
    }
    let cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
    Ok(([(header::SET_COOKIE, cookie)], Json(json!({"ok": true}))).into_response())
}

// ---------- helpers ----------

/// The URL nodes and subscription clients use for this master.
pub fn base_url(app: &App, headers: &HeaderMap) -> String {
    if let Some(u) = db::get_setting(&app.db(), "panel_url").ok().flatten().filter(|u| !u.is_empty()) {
        return u.trim_end_matches('/').to_string();
    }
    // The host ends up in a shell command run as root: plain host[:port] only.
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b)))
        .unwrap_or("localhost");
    // Behind a reverse proxy assume HTTPS unless it says plain http: falling
    // back to http would send node tokens and configs in the clear.
    let scheme = if app.tls.is_some() {
        "https"
    } else {
        match headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).map(str::trim) {
            Some("http") => "http",
            _ => "https",
        }
    };
    format!("{scheme}://{host}")
}

pub fn install_command(app: &App, base: &str, token: &str) -> String {
    let pin = app.tls.as_ref().and_then(|t| t.spki_pin.as_ref());
    let curl = match pin {
        Some(p) => format!("curl -fsSLk --pinnedpubkey 'sha256//{p}'"),
        None => "curl -fsSL".to_string(),
    };
    // The token goes in the environment of sh, not its arguments: other users
    // can list arguments while the installer runs, not another user's environment.
    let mut cmd = format!("{curl} '{base}/install.sh' | KEEL_TOKEN='{token}' sh -s -- --master '{base}'");
    if let (Some(p), Some(t)) = (pin, &app.tls) {
        // Nodes pin the key, not the certificate, so the panel can later get a
        // CA certificate for the same key without reinstalling them.
        cmd.push_str(&format!(" --fingerprint {} --pin '{p}'", t.spki_sha256));
    }
    cmd
}

fn str_field(v: &Value, max: usize) -> Result<String, Response> {
    let s = v.as_str().ok_or_else(|| bad("应为文字"))?.trim().to_string();
    if s.chars().count() > max {
        return Err(bad(format!("太长了（最多 {max} 个字）")));
    }
    Ok(s)
}

fn port_field(v: &Value) -> Result<i64, Response> {
    let p = v.as_i64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).ok_or_else(|| bad("端口应为数字"))?;
    if !(1..=65535).contains(&p) {
        return Err(bad("端口应在 1–65535"));
    }
    Ok(p)
}

fn int_field(v: &Value, min: i64, max: i64) -> Result<i64, Response> {
    let n = v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)).ok_or_else(|| bad("应为数字"))?;
    if n < min || n > max {
        return Err(bad(format!("应在 {min}–{max}")));
    }
    Ok(n)
}

fn bool_field(v: &Value) -> Result<bool, Response> {
    v.as_bool().ok_or_else(|| bad("应为开或关"))
}

fn exists(conn: &Connection, table: &str, id: i64) -> bool {
    conn.query_row(&format!("SELECT 1 FROM {table} WHERE id=?1"), [id], |_| Ok(())).is_ok()
}

// ---------- state ----------

pub async fn state(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    ok(state_value(&app, &headers)?)
}

/// The public status page at /: per-node health and probes only. No
/// addresses, ports, tokens, users, routes or exits, so it is safe to show
/// without logging in.
/// Whether the anonymous probe page at / is on (a setting, off by default).
pub fn public_page(app: &App) -> bool {
    db::get_setting(&app.db(), "public_page").ok().flatten().is_some_and(|v| v == "1")
}

pub async fn public_state(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult {
    if !public_page(&app) {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    // Anyone may ask, so the answer is built at most once per interval, by
    // one request at a time and off the async workers; everyone else gets
    // the copy.
    static CACHE: tokio::sync::Mutex<Option<(std::time::Instant, Value)>> = tokio::sync::Mutex::const_new(None);
    const FRESH: Duration = Duration::from_secs(2);
    let mut cache = CACHE.lock().await;
    if let Some((_, v)) = cache.as_ref().filter(|(at, _)| at.elapsed() < FRESH) {
        return ok(v.clone());
    }
    let v = tokio::task::spawn_blocking(move || public_value(&app, &headers)).await.map_err(internal)??;
    *cache = Some((std::time::Instant::now(), v.clone()));
    ok(v)
}

fn public_value(app: &Arc<App>, headers: &HeaderMap) -> Result<Value, Response> {
    let full = state_value(app, headers)?;
    const KEEP: &[&str] = &["id", "name", "role", "online", "last_seen", "month_rx", "month_tx", "probes", "checks"];
    const SYSTEM: &[&str] = &["cpu_pct", "mem_total", "mem_used", "disk_total", "disk_used", "rx_rate", "tx_rate", "uptime_s", "tcp_retrans_pct"];
    let pick = |v: &Value, keys: &[&str]| -> Value {
        let mut o = Map::new();
        for k in keys {
            if let Some(x) = v.get(*k) {
                o.insert((*k).to_string(), x.clone());
            }
        }
        Value::Object(o)
    };
    let nodes: Vec<Value> = full["nodes"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|n| {
                    let mut o = pick(n, KEEP);
                    if n["system"].is_object() {
                        o["system"] = pick(&n["system"], SYSTEM);
                    }
                    o
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({"now": full["now"], "nodes": nodes, "summary": full["summary"]}))
}

fn state_value(app: &Arc<App>, headers: &HeaderMap) -> Result<Value, Response> {
    let ts = now();
    let base = base_url(&app, &headers);
    let conn = app.db();
    let w = db::load_world(&conn).map_err(internal)?;
    let months = db::node_months(&conn, &month_label(ts, w.tz)).map_err(internal)?;
    let targets = App::probe_targets(&conn);
    let panel_url = db::get_setting(&conn, "panel_url").ok().flatten().unwrap_or_default();
    let username = admin_user(&conn);
    let public_page = db::get_setting(&conn, "public_page").ok().flatten().is_some_and(|v| v == "1");
    let panel_acme = db::get_setting(&conn, "panel_acme").ok().flatten().is_some_and(|v| v == "1");
    drop(conn);
    let live = app.live();

    let mut month_total = 0i64;
    let mut online = 0;
    let nodes: Vec<Value> = w
        .nodes
        .iter()
        .map(|n| {
            let mut v = serde_json::to_value(n).unwrap_or_default();
            let o = v.as_object_mut().expect("object");
            let (mrx, mtx) = months.get(&n.id).copied().unwrap_or((0, 0));
            month_total += mrx + mtx;
            o.insert("month_rx".into(), json!(mrx));
            o.insert("month_tx".into(), json!(mtx));
            o.insert("token_tail".into(), json!(tail(&n.token, 4)));
            o.insert("address".into(), json!(n.address()));
            if let Some(d) = crate::dns::status(n.id) {
                o.insert("dns".into(), json!(d));
            }
            o.insert(
                "rules".into(),
                json!(w
                    .rules_of(n.id)
                    .map(|r| json!({"ruleset": r.ruleset, "exit_id": r.exit_id, "fallback": r.fallback}))
                    .collect::<Vec<_>>()),
            );
            let l = live.nodes.get(&n.id);
            let is_online = l.is_some_and(|l| l.online());
            if is_online {
                online += 1;
            }
            o.insert("online".into(), json!(is_online));
            if let Some(l) = l {
                o.insert("last_seen".into(), json!(l.last_seen));
                o.insert("connected_at".into(), json!(l.connected_at));
                o.insert("version".into(), json!(l.hello.node_version));
                o.insert("protocols".into(), json!(l.hello.protocols));
                o.insert("system".into(), json!(l.system));
                o.insert("conns".into(), json!(l.conns.values().sum::<i64>()));
                o.insert("applied_rev".into(), json!(l.applied_rev));
                o.insert("sent_rev".into(), json!(l.sent_rev));
                o.insert("apply_error".into(), json!(l.apply_error));
                o.insert("health".into(), json!(l.outbounds));
                o.insert("certs".into(), json!(l.certs));
                let probes: Vec<Value> = targets
                    .iter()
                    .filter_map(|t| {
                        let h = l.probes.get(&t.name)?;
                        let last = h.back()?;
                        let ok: Vec<f64> = h.iter().map(|p| p.latency).filter(|x| *x > 0.0).collect();
                        Some(json!({
                            "name": t.name, "label": t.label,
                            "latency": last.latency, "jitter": last.jitter, "loss": last.loss,
                            "min": ok.iter().cloned().fold(f64::INFINITY, f64::min).min(1e9),
                            "max": ok.iter().cloned().fold(0.0, f64::max),
                            "points": h.iter().map(|p| (p.latency * 10.0).round() / 10.0).collect::<Vec<_>>(),
                            "since": h.front().map(|p| p.ts),
                        }))
                    })
                    .collect();
                if n.is_entry() {
                    o.insert("probes".into(), json!(probes));
                }
            }
            // Exits are not probed; they are judged by how the entries reach them.
            if !n.is_entry() {
                let checks: Vec<Value> = w
                    .nodes
                    .iter()
                    .filter(|en| en.is_entry())
                    .filter_map(|en| {
                        let l = live.nodes.get(&en.id)?;
                        let h = w.exits.iter().filter(|x| x.node_id == n.id).find_map(|x| l.outbounds.get(&format!("x{}", x.id)))?;
                        let name = if en.name.is_empty() { &en.code } else { &en.name };
                        Some(json!({"name": name, "alive": h.alive, "latency_ms": h.latency_ms}))
                    })
                    .collect();
                o.insert("checks".into(), json!(checks));
            }
            v
        })
        .collect();

    let exits: Vec<Value> = w
        .exits
        .iter()
        .map(|e| {
            let mut v = serde_json::to_value(e).unwrap_or_default();
            let o = v.as_object_mut().expect("object");
            o.insert("used".into(), json!(nodecfg::exit_used(&w, e, ts)));
            o.insert("period_end".into(), json!(period_end(ts, w.tz, e.reset_day as u32)));
            v
        })
        .collect();

    let users: Vec<Value> = w
        .users
        .iter()
        .map(|u| {
            let used = nodecfg::user_used(&w, u, ts);
            let status = if !u.enabled {
                "disabled"
            } else if u.expire_at > 0 && ts >= u.expire_at {
                "expired"
            } else if u.quota_bytes > 0 && used >= u.quota_bytes {
                "over"
            } else if u.quota_bytes > 0 && used * 10 >= u.quota_bytes * 9 {
                "warn"
            } else {
                "ok"
            };
            let counter = nodecfg::user_counter(u.id);
            let conns: i64 = live.nodes.values().filter_map(|l| l.conns.get(&counter)).sum();
            let mut v = serde_json::to_value(u).unwrap_or_default();
            let o = v.as_object_mut().expect("object");
            o.insert("used".into(), json!(used));
            o.insert("status".into(), json!(status));
            o.insert("conns".into(), json!(conns));
            o.insert("expire_date".into(), json!(format_date_end(u.expire_at, w.tz)));
            o.insert("period_end".into(), json!(period_end(ts, w.tz, u.reset_day as u32)));
            o.insert("entries".into(), json!(w.user_entries.get(&u.id).cloned().unwrap_or_default()));
            o.insert("sub_url".into(), json!(format!("{base}/s/{}", u.sub_token)));
            v
        })
        .collect();

    Ok(json!({
        "now": ts,
        "nodes": nodes,
        "exits": exits,
        "rulesets": w.rulesets,
        "users": users,
        "summary": {
            "speed": live.speed.iter().map(|(rx, tx)| [rx.round(), tx.round()]).collect::<Vec<_>>(),
            "online": online,
            "month": month_total,
        },
        "settings": {
            "username": username,
            "panel_url": panel_url,
            "public_page": public_page,
            "panel_acme": panel_acme,
            "panel_acme_available": app.panel_tls.is_some(),
            "panel_cert": crate::panel_cert::status(),
            "base_url": base,
            "tz_offset": w.tz,
            "probe_targets": targets,
            "fingerprint": app.tls.as_ref().map(|t| t.cert_sha256.clone()),
            "acme_email": w.acme_email,
            // Never sent back: only whether it is set and its last 4 chars.
            "cf_token_tail": tail(&w.cf_token, 4),
        },
    }))
}

// ---------- nodes ----------

#[derive(Deserialize)]
pub struct NewNode {
    role: String,
    #[serde(default)]
    code: String,
    name: String,
}

pub async fn create_node(State(app): State<Arc<App>>, headers: HeaderMap, Json(b): Json<NewNode>) -> ApiResult {
    if b.role != "entry" && b.role != "exit" {
        return Err(bad("角色只能是入口或出口"));
    }
    let name = str_field(&json!(b.name), 40)?;
    // The panel shows only the name; the code stays as an internal short id.
    let mut code = str_field(&json!(b.code), 8)?.to_uppercase();
    if code.is_empty() {
        code = format!("N{}", random_hex(3).to_uppercase());
    }
    if name.is_empty() {
        return Err(bad("请填名称"));
    }
    let id = {
        let conn = app.db();
        let id = db::insert_node(&conn, &b.role, &code, if name.is_empty() { &code } else { &name }, now()).map_err(internal)?;
        if b.role == "exit" {
            conn.execute(
                "INSERT INTO exits(id,node_id,name,port,psk,reset_day,sort) VALUES(?5,?1,?2,?3,?4,1,0)",
                params![id, code, crate::util::random_port(&[]), random_b64(16), db::fresh_id(&conn, "exits").map_err(internal)?],
            )
            .map_err(internal)?;
        }
        id
    };
    let token: String = app.db().query_row("SELECT token FROM nodes WHERE id=?1", [id], |r| r.get(0)).map_err(internal)?;
    let base = base_url(&app, &headers);
    ok(json!({"id": id, "install": install_command(&app, &base, &token)}))
}

/// uTLS fingerprints clients may present for Reality.
const FINGERPRINTS: &[&str] = &["chrome", "firefox", "safari", "ios", "android", "edge", "random"];

pub async fn update_node(State(app): State<Arc<App>>, Path(id): Path<i64>, Json(b): Json<Map<String, Value>>) -> ApiResult {
    {
        let conn = app.db();
        if !exists(&conn, "nodes", id) {
            return Err(bad("没有这个节点"));
        }
        for (k, v) in &b {
            let (col, val): (&str, Value) = match k.as_str() {
                "code" => {
                    let s = str_field(v, 8)?.to_uppercase();
                    if s.is_empty() {
                        return Err(bad("代号不能为空"));
                    }
                    ("code", json!(s))
                }
                "name" => ("name", json!(str_field(v, 40)?)),
                "host" => ("host", json!(str_field(v, 255)?)),
                "direct_list" => ("direct_list", json!(str_field(v, 200_000)?)),
                "anytls_sni" => ("anytls_sni", json!(str_field(v, 255)?)),
                "anytls_cert" | "anytls_key" => {
                    let s = str_field(v, 255)?;
                    if !s.is_empty() && !s.starts_with('/') {
                        return Err(bad("证书路径要写服务器上的绝对路径，比如 /etc/letsencrypt/live/域名/fullchain.pem"));
                    }
                    (k.as_str(), json!(s))
                }
                "reality_dest" => {
                    let s = str_field(v, 255)?;
                    if !s.is_empty() && !s.rsplit_once(':').is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok()) {
                        return Err(bad("Reality 目标要写成 域名:端口，比如 www.apple.com:443"));
                    }
                    ("reality_dest", json!(s))
                }
                "reality_sni" => {
                    let names = db::split_list(&str_field(v, 1000)?);
                    if names.is_empty() {
                        return Err(bad("Reality SNI 至少填一个"));
                    }
                    ("reality_sni", json!(names.join(",")))
                }
                "reality_short_id" => {
                    let ids = db::split_list(&str_field(v, 500)?);
                    if ids.is_empty() || ids.iter().any(|i| i.len() > 16 || i.len() % 2 != 0 || !i.chars().all(|c| c.is_ascii_hexdigit())) {
                        return Err(bad("Short ID 是 0–16 位偶数长度的十六进制，多个用逗号隔开"));
                    }
                    ("reality_short_id", json!(ids.join(",").to_lowercase()))
                }
                "reality_fp" => {
                    let s = str_field(v, 20)?;
                    if !FINGERPRINTS.contains(&s.as_str()) {
                        return Err(bad("不支持这个指纹"));
                    }
                    ("reality_fp", json!(s))
                }
                "reality_regen" => {
                    if v.as_bool() == Some(true) {
                        let (private, public) = crate::util::reality_keypair();
                        conn.execute("UPDATE nodes SET reality_private=?1, reality_public=?2 WHERE id=?3", params![private, public, id]).map_err(internal)?;
                    }
                    continue;
                }
                "ipv4_only" | "anytls_on" | "vless_on" | "ss_on" | "anytls_acme" => (k.as_str(), json!(bool_field(v)?)),
                "anytls_port" | "vless_port" | "ss_port" => (k.as_str(), json!(port_field(v)?)),
                "anytls_pub" | "vless_pub" => (k.as_str(), json!(if v.is_null() || v.as_i64() == Some(0) { 0 } else { port_field(v)? })),
                "default_exit" => {
                    let e = int_field(v, 0, i64::MAX)?;
                    if e != 0 && !exists(&conn, "exits", e) {
                        return Err(bad("没有这个出口"));
                    }
                    ("default_exit", json!(e))
                }
                "default_fallback" => ("default_fallback", json!(db::ids_to_text(&exit_list(&conn, v)?))),
                _ => return Err(bad(format!("不能改 {k}"))),
            };
            let val: rusqlite::types::Value = match val {
                Value::Bool(b) => rusqlite::types::Value::Integer(b as i64),
                Value::Number(n) => rusqlite::types::Value::Integer(n.as_i64().unwrap_or(0)),
                Value::String(s) => rusqlite::types::Value::Text(s),
                _ => rusqlite::types::Value::Null,
            };
            conn.execute(&format!("UPDATE nodes SET {col}=?1 WHERE id=?2"), params![val, id]).map_err(internal)?;
        }
    }
    app.sync();
    crate::dns::spawn_sync(app.clone());
    ok(json!({"ok": true}))
}

#[derive(Deserialize)]
pub struct Rules {
    rules: Vec<RuleRow>,
}

#[derive(Deserialize)]
pub struct RuleRow {
    ruleset: String,
    exit_id: i64,
    #[serde(default)]
    fallback: Vec<i64>,
}

/// An ordered list of fallback exits (0 = direct), checked and deduplicated.
fn exit_list(conn: &Connection, v: &Value) -> Result<Vec<i64>, Response> {
    let mut out = Vec::new();
    for id in v.as_array().ok_or_else(|| bad("备用出口应为列表"))?.iter() {
        let id = id.as_i64().ok_or_else(|| bad("备用出口应为编号"))?;
        if id != 0 && !exists(conn, "exits", id) {
            return Err(bad("没有这个出口"));
        }
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

pub async fn set_rules(State(app): State<Arc<App>>, Path(id): Path<i64>, Json(b): Json<Rules>) -> ApiResult {
    {
        let mut conn = app.db();
        let tx = conn.transaction().map_err(internal)?;
        let role: String = tx.query_row("SELECT role FROM nodes WHERE id=?1", [id], |r| r.get(0)).map_err(|_| bad("没有这个节点"))?;
        if role != "entry" {
            return Err(bad("只有入口有分流"));
        }
        tx.execute("DELETE FROM entry_rules WHERE node_id=?1", [id]).map_err(internal)?;
        for (i, r) in b.rules.iter().enumerate() {
            if r.exit_id != 0 && !exists(&tx, "exits", r.exit_id) {
                return Err(bad("没有这个出口"));
            }
            let fallback = exit_list(&tx, &json!(r.fallback))?;
            let fallback: Vec<i64> = fallback.into_iter().filter(|x| *x != r.exit_id).collect();
            tx.execute(
                "INSERT OR REPLACE INTO entry_rules(node_id,ruleset,exit_id,sort,fallback) VALUES(?1,?2,?3,?4,?5)",
                params![id, r.ruleset, r.exit_id, i as i64, db::ids_to_text(&fallback)],
            )
            .map_err(|_| bad("没有这个规则集"))?;
        }
        tx.commit().map_err(internal)?;
    }
    app.sync();
    ok(json!({"ok": true}))
}

pub async fn rotate_token(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<i64>) -> ApiResult {
    let token = random_hex(24);
    // Everything the old token could fetch is replaced too: the entry's keys
    // on every exit, and the PSKs of the exit ports this node runs.
    let n = {
        let conn = app.db();
        let n = conn.execute("UPDATE nodes SET token=?1, key_salt=?2 WHERE id=?3", params![token, random_hex(16), id]).map_err(internal)?;
        let ports: Vec<i64> = {
            let mut st = conn.prepare("SELECT id FROM exits WHERE node_id=?1").map_err(internal)?;
            let rows = st.query_map([id], |r| r.get(0)).map_err(internal)?;
            rows.collect::<Result<_, _>>().map_err(internal)?
        };
        for e in ports {
            conn.execute("UPDATE exits SET psk=?1 WHERE id=?2", params![random_b64(16), e]).map_err(internal)?;
        }
        n
    };
    if n == 0 {
        return Err(bad("没有这个节点"));
    }
    app.kick(id);
    app.sync();
    let base = base_url(&app, &headers);
    ok(json!({"install": install_command(&app, &base, &token)}))
}

pub async fn install_of(State(app): State<Arc<App>>, headers: HeaderMap, Path(id): Path<i64>) -> ApiResult {
    let token: String =
        app.db().query_row("SELECT token FROM nodes WHERE id=?1", [id], |r| r.get(0)).map_err(|_| bad("没有这个节点"))?;
    let base = base_url(&app, &headers);
    ok(json!({"install": install_command(&app, &base, &token)}))
}

pub async fn delete_node(State(app): State<Arc<App>>, Path(id): Path<i64>) -> ApiResult {
    {
        let mut conn = app.db();
        let tx = conn.transaction().map_err(internal)?;
        let exits: Vec<i64> = {
            let mut st = tx.prepare("SELECT id FROM exits WHERE node_id=?1").map_err(internal)?;
            let rows = st.query_map([id], |r| r.get(0)).map_err(internal)?;
            rows.collect::<Result<_, _>>().map_err(internal)?
        };
        for e in exits {
            forget_exit(&tx, e).map_err(internal)?;
        }
        tx.execute("DELETE FROM nodes WHERE id=?1", [id]).map_err(internal)?;
        tx.commit().map_err(internal)?;
    }
    app.kick(id);
    app.live().nodes.remove(&id);
    app.sync();
    ok(json!({"ok": true}))
}

/// Takes an exit out of every default and rule: its first fallback moves
/// up, and a rule left with nothing goes back to the default exit.
fn forget_exit(conn: &Connection, exit: i64) -> rusqlite::Result<()> {
    let promote = |primary: i64, fallback: &str| -> (i64, String) {
        let mut rest: Vec<i64> = db::ids_from_text(fallback).into_iter().filter(|x| *x != exit).collect();
        let primary = if primary == exit { if rest.is_empty() { -1 } else { rest.remove(0) } } else { primary };
        (primary, db::ids_to_text(&rest))
    };
    let nodes: Vec<(i64, i64, String)> = conn
        .prepare("SELECT id, default_exit, default_fallback FROM nodes")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    for (id, primary, fallback) in nodes {
        let (p, f) = promote(primary, &fallback);
        conn.execute("UPDATE nodes SET default_exit=?1, default_fallback=?2 WHERE id=?3", params![p.max(0), f, id])?;
    }
    let rules: Vec<(i64, String, i64, String)> = conn
        .prepare("SELECT node_id, ruleset, exit_id, fallback FROM entry_rules")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<Result<_, _>>()?;
    for (node, set, primary, fallback) in rules {
        let (p, f) = promote(primary, &fallback);
        if p < 0 {
            conn.execute("DELETE FROM entry_rules WHERE node_id=?1 AND ruleset=?2", params![node, set])?;
        } else {
            conn.execute("UPDATE entry_rules SET exit_id=?1, fallback=?2 WHERE node_id=?3 AND ruleset=?4", params![p, f, node, set])?;
        }
    }
    conn.execute("DELETE FROM exits WHERE id=?1", [exit])?;
    Ok(())
}

// ---------- exits ----------

fn apply_exit_fields(conn: &Connection, id: i64, b: &Map<String, Value>) -> Result<(), Response> {
    for (k, v) in b {
        let (col, val): (&str, rusqlite::types::Value) = match k.as_str() {
            "name" => {
                let s = str_field(v, 40)?;
                if s.is_empty() {
                    return Err(bad("名称不能为空"));
                }
                ("name", s.into())
            }
            "port" => ("port", port_field(v)?.into()),
            "pub_port" => ("pub_port", (if v.is_null() || v.as_i64() == Some(0) { 0 } else { port_field(v)? }).into()),
            "quota_bytes" => ("quota_bytes", int_field(v, 0, i64::MAX / 2)?.into()),
            "reset_day" => ("reset_day", int_field(v, 1, 31)?.into()),
            "udp_over_tcp" => ("udp_over_tcp", (bool_field(v)? as i64).into()),
            "node_id" | "link" => continue,
            _ => return Err(bad(format!("不能改 {k}"))),
        };
        conn.execute(&format!("UPDATE exits SET {col}=?1 WHERE id=?2"), params![val, id]).map_err(internal)?;
    }
    Ok(())
}

/// Saves imported servers as external exits; returns their ids.
fn import_exits(conn: &mut Connection, text: &str, name: Option<&str>) -> Result<Vec<i64>, Response> {
    let items = link::parse_all(text).map_err(bad)?;
    let tx = conn.transaction().map_err(internal)?;
    let mut sort: i64 = tx.query_row("SELECT COALESCE(MAX(sort),0)+1 FROM exits", [], |r| r.get(0)).map_err(internal)?;
    let mut ids = Vec::new();
    for it in &items {
        let name = match name {
            Some(n) if items.len() == 1 && !n.trim().is_empty() => n.trim().to_string(),
            _ if it.name.is_empty() => it.server.clone(),
            _ => it.name.clone(),
        };
        tx.execute(
            "INSERT INTO exits(id,node_id,name,kind,server,uuid,method,psk,sort,tls_sni) VALUES(?8,NULL,?1,?2,?3,?4,?5,?6,?7,?9)",
            params![name.chars().take(40).collect::<String>(), it.kind, it.server, it.uuid, it.method, it.password, sort, db::fresh_id(&tx, "exits").map_err(internal)?, it.tls_sni],
        )
        .map_err(internal)?;
        ids.push(tx.last_insert_rowid());
        sort += 1;
    }
    tx.commit().map_err(internal)?;
    Ok(ids)
}

/// Re-imports an external exit's server from a new link, keeping its name,
/// routes and fallbacks.
fn reimport_exit(conn: &Connection, id: i64, text: &str) -> Result<(), Response> {
    let mut items = link::parse_all(text).map_err(bad)?;
    if items.len() != 1 {
        return Err(bad("换链接时只能粘一条"));
    }
    let it = items.remove(0);
    let n = conn
        .execute(
            "UPDATE exits SET kind=?1, server=?2, uuid=?3, method=?4, psk=?5, tls_sni=?7 WHERE id=?6 AND node_id IS NULL",
            params![it.kind, it.server, it.uuid, it.method, it.password, id, it.tls_sni],
        )
        .map_err(internal)?;
    if n == 0 {
        return Err(bad("只有外部出口能换链接"));
    }
    Ok(())
}

pub async fn create_exit(State(app): State<Arc<App>>, Json(b): Json<Map<String, Value>>) -> ApiResult {
    if let Some(text) = b.get("link").and_then(Value::as_str) {
        let ids = import_exits(&mut app.db(), text, b.get("name").and_then(Value::as_str))?;
        app.sync();
        return ok(json!({"id": ids[0], "ids": ids}));
    }
    let id = {
        let mut conn = app.db();
        let tx = conn.transaction().map_err(internal)?;
        let node = b.get("node_id").and_then(Value::as_i64).ok_or_else(|| bad("缺少节点"))?;
        let role: String = tx.query_row("SELECT role FROM nodes WHERE id=?1", [node], |r| r.get(0)).map_err(|_| bad("没有这个节点"))?;
        if role != "exit" {
            return Err(bad("只有出口节点能加 SS 端口"));
        }
        let taken: Vec<i64> = tx
            .prepare("SELECT port FROM exits WHERE node_id=?1")
            .and_then(|mut st| st.query_map([node], |r| r.get(0))?.collect())
            .map_err(internal)?;
        let count = taken.len() as i64;
        tx.execute(
            "INSERT INTO exits(id,node_id,name,port,psk,reset_day,sort) VALUES(?6,?1,?2,?3,?4,1,?5)",
            params![node, format!("出口 {}", count + 1), crate::util::random_port(&taken), random_b64(16), count, db::fresh_id(&tx, "exits").map_err(internal)?],
        )
        .map_err(internal)?;
        let id = tx.last_insert_rowid();
        apply_exit_fields(&tx, id, &b)?;
        tx.commit().map_err(internal)?;
        id
    };
    app.sync();
    ok(json!({"id": id}))
}

pub async fn update_exit(State(app): State<Arc<App>>, Path(id): Path<i64>, Json(b): Json<Map<String, Value>>) -> ApiResult {
    {
        let conn = app.db();
        if !exists(&conn, "exits", id) {
            return Err(bad("没有这个出口"));
        }
        if let Some(text) = b.get("link").and_then(Value::as_str).filter(|t| !t.trim().is_empty()) {
            reimport_exit(&conn, id, text)?;
        }
        apply_exit_fields(&conn, id, &b)?;
    }
    app.sync();
    ok(json!({"ok": true}))
}

pub async fn delete_exit(State(app): State<Arc<App>>, Path(id): Path<i64>) -> ApiResult {
    {
        let mut conn = app.db();
        let tx = conn.transaction().map_err(internal)?;
        forget_exit(&tx, id).map_err(internal)?;
        tx.commit().map_err(internal)?;
    }
    app.sync();
    ok(json!({"ok": true}))
}

// ---------- users ----------

fn apply_user_fields(conn: &Connection, id: i64, b: &Map<String, Value>, tz: i64) -> Result<(), Response> {
    for (k, v) in b {
        let (col, val): (&str, rusqlite::types::Value) = match k.as_str() {
            "name" => {
                let s = str_field(v, 40)?;
                if s.is_empty() {
                    return Err(bad("名称不能为空"));
                }
                ("name", s.into())
            }
            "plan" => ("plan", str_field(v, 20)?.into()),
            "quota_bytes" => ("quota_bytes", int_field(v, 0, i64::MAX / 2)?.into()),
            "reset_day" => ("reset_day", int_field(v, 1, 31)?.into()),
            "enabled" => ("enabled", (bool_field(v)? as i64).into()),
            "expire_date" => {
                let s = str_field(v, 10)?;
                let ts = parse_date_end(&s, tz).ok_or_else(|| bad("到期日期格式应为 2027-03-01，留空为不限"))?;
                ("expire_at", ts.into())
            }
            "entries" => {
                let ids: Vec<i64> = v
                    .as_array()
                    .ok_or_else(|| bad("入口应为列表"))?
                    .iter()
                    .filter_map(Value::as_i64)
                    .collect();
                conn.execute("DELETE FROM user_entries WHERE user_id=?1", [id]).map_err(internal)?;
                for n in ids {
                    conn.execute(
                        "INSERT OR IGNORE INTO user_entries(user_id,node_id) SELECT ?1, id FROM nodes WHERE id=?2 AND role='entry'",
                        params![id, n],
                    )
                    .map_err(internal)?;
                }
                continue;
            }
            _ => return Err(bad(format!("不能改 {k}"))),
        };
        conn.execute(&format!("UPDATE users SET {col}=?1 WHERE id=?2"), params![val, id]).map_err(internal)?;
    }
    Ok(())
}

fn tz_of(conn: &Connection) -> i64 {
    db::get_setting(conn, "tz_offset").ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(480)
}

pub async fn create_user(State(app): State<Arc<App>>, Json(b): Json<Map<String, Value>>) -> ApiResult {
    let name = b.get("name").map(|v| str_field(v, 40)).transpose()?.unwrap_or_default();
    if name.is_empty() {
        return Err(bad("请填用户名"));
    }
    let id = {
        let mut conn = app.db();
        let tz = tz_of(&conn);
        let tx = conn.transaction().map_err(internal)?;
        let id = db::insert_user(&tx, &name, now()).map_err(internal)?;
        apply_user_fields(&tx, id, &b, tz)?;
        tx.commit().map_err(internal)?;
        id
    };
    app.sync();
    ok(json!({"id": id}))
}

pub async fn update_user(State(app): State<Arc<App>>, Path(id): Path<i64>, Json(b): Json<Map<String, Value>>) -> ApiResult {
    {
        let mut conn = app.db();
        let tz = tz_of(&conn);
        let tx = conn.transaction().map_err(internal)?;
        if !exists(&tx, "users", id) {
            return Err(bad("没有这个用户"));
        }
        apply_user_fields(&tx, id, &b, tz)?;
        tx.commit().map_err(internal)?;
    }
    app.sync();
    ok(json!({"ok": true}))
}

/// Starts the user's counters from zero now: a new period label makes every
/// node drop its count, and the master's sums only look at the new label.
pub async fn reset_user(State(app): State<Arc<App>>, Path(id): Path<i64>) -> ApiResult {
    {
        let conn = app.db();
        let w = db::load_world(&conn).map_err(internal)?;
        let u = w.users.iter().find(|u| u.id == id).ok_or_else(|| bad("没有这个用户"))?;
        let base = crate::period::period_label(now(), w.tz, u.reset_day as u32, 0);
        let seq = if u.reset_period == base { u.reset_seq + 1 } else { 1 };
        conn.execute("UPDATE users SET reset_period=?1, reset_seq=?2 WHERE id=?3", params![base, seq, id]).map_err(internal)?;
    }
    app.sync();
    ok(json!({"ok": true}))
}

/// A new subscription link comes with new proxy credentials: a leaked link
/// is only revoked if what it handed out stops working too.
pub async fn rotate_sub(State(app): State<Arc<App>>, Path(id): Path<i64>) -> ApiResult {
    let n = app
        .db()
        .execute(
            "UPDATE users SET sub_token=?1, anytls_password=?2, uuid=?3, ss_key=?4, per_entry=1 WHERE id=?5",
            params![random_hex(16), random_hex(16), crate::util::random_uuid(), random_b64(16), id],
        )
        .map_err(internal)?;
    if n == 0 {
        return Err(bad("没有这个用户"));
    }
    app.sync();
    ok(json!({"ok": true}))
}

pub async fn delete_user(State(app): State<Arc<App>>, Path(id): Path<i64>) -> ApiResult {
    app.db().execute("DELETE FROM users WHERE id=?1", [id]).map_err(internal)?;
    app.sync();
    ok(json!({"ok": true}))
}

// ---------- settings ----------

pub async fn update_settings(State(app): State<Arc<App>>, headers: HeaderMap, Json(b): Json<Map<String, Value>>) -> ApiResult {
    // The current password (needed to change the name or password) counts
    // against the same failure limit as logins, and is checked off the async
    // workers without holding the database.
    let current_ok = match b.get("current_password").and_then(Value::as_str).filter(|p| !p.is_empty()) {
        None => false,
        Some(pw) => {
            let key = format!("settings:{}", session_token(&headers).unwrap_or_default());
            if locked_out(&key, true) {
                return Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "试错太多次，10 分钟后再试"}))).into_response());
            }
            let stored = db::get_setting(&app.db(), "admin_hash").ok().flatten();
            let pw = pw.to_string();
            let _permit = VERIFYING.acquire().await.map_err(internal)?;
            let good = tokio::task::spawn_blocking(move || stored.is_some_and(|h| password_matches(&h, &pw))).await.unwrap_or(false);
            if !good {
                record_failure(&key);
            }
            good
        }
    };
    {
        let conn = app.db();
        // A new name or password signs out every other session.
        let sign_out_others = || {
            let current = session_token(&headers).unwrap_or_default();
            conn.execute("DELETE FROM sessions WHERE token<>?1", [current]).map_err(internal)
        };
        if let Some(v) = b.get("username") {
            let name = str_field(v, 40)?;
            if name.is_empty() {
                return Err(bad("用户名不能为空"));
            }
            if name != admin_user(&conn) {
                if !current_ok {
                    return Err(bad("改用户名要填当前密码"));
                }
                db::set_setting(&conn, "admin_user", &name).map_err(internal)?;
                sign_out_others()?;
            }
        }
        if let Some(pw) = b.get("password") {
            let pw = pw.as_str().unwrap_or("");
            if !current_ok {
                return Err(bad("当前密码不对"));
            }
            if pw.chars().count() < 8 {
                return Err(bad("新密码至少 8 位"));
            }
            db::set_setting(&conn, "admin_hash", &hash_password(pw)).map_err(internal)?;
            sign_out_others()?;
        }
        if let Some(v) = b.get("panel_url") {
            let u = str_field(v, 255)?;
            let rest = u.strip_prefix("https://").or_else(|| u.strip_prefix("http://"));
            let plain = rest.is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]/_~".contains(&b)));
            if !u.is_empty() && !plain {
                return Err(bad("面板地址应像 https://panel.example.com:8443"));
            }
            db::set_setting(&conn, "panel_url", u.trim_end_matches('/')).map_err(internal)?;
        }
        if let Some(v) = b.get("acme_email") {
            let s = str_field(v, 120)?;
            if !s.is_empty() && !s.contains('@') {
                return Err(bad("邮箱格式不对"));
            }
            db::set_setting(&conn, "acme_email", &s).map_err(internal)?;
        }
        // Empty or missing leaves the token as is; "-" clears it.
        if let Some(v) = b.get("cf_token") {
            let s = str_field(v, 200)?;
            if s == "-" {
                db::set_setting(&conn, "cf_token", "").map_err(internal)?;
            } else if !s.is_empty() {
                db::set_setting(&conn, "cf_token", &s).map_err(internal)?;
            }
        }
        if let Some(v) = b.get("panel_acme") {
            db::set_setting(&conn, "panel_acme", if bool_field(v)? { "1" } else { "0" }).map_err(internal)?;
        }
        if let Some(v) = b.get("public_page") {
            db::set_setting(&conn, "public_page", if bool_field(v)? { "1" } else { "0" }).map_err(internal)?;
        }
        if let Some(v) = b.get("tz_offset") {
            db::set_setting(&conn, "tz_offset", &int_field(v, -720, 840)?.to_string()).map_err(internal)?;
        }
        if let Some(v) = b.get("probe_targets") {
            let targets: Vec<ProbeTarget> = serde_json::from_value(v.clone()).map_err(|_| bad("测速目标格式不对"))?;
            if targets.len() > 8 {
                return Err(bad("测速目标最多 8 个"));
            }
            for t in &targets {
                let short = |s: &str, n: usize| !s.is_empty() && s.len() <= n && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                if !short(&t.name, 16) || t.label.chars().count() > 20 || t.host.len() > 255 {
                    return Err(bad("测速目标的名字或地址不对"));
                }
                if !t.host.is_empty() && !t.host.contains(':') {
                    return Err(bad(format!("{} 的地址要带端口，比如 1.2.3.4:80", t.label)));
                }
            }
            db::set_setting(&conn, "probe_targets", &serde_json::to_string(&targets).unwrap_or_default()).map_err(internal)?;
        }
    }
    app.sync();
    crate::dns::spawn_sync(app.clone());
    crate::panel_cert::kick();
    ok(json!({"ok": true}))
}
