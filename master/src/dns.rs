//! Points each entry's AnyTLS domain at the node through the Cloudflare API,
//! when a Cloudflare token is set: one A (or AAAA) record per domain, not
//! proxied, so clients reach the node directly. Records already right are
//! left alone; the last result per node is kept for the panel.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::app::App;
use crate::db;

const API_HOST: &str = "api.cloudflare.com";

#[derive(Clone, serde::Serialize)]
pub struct Status {
    pub name: String,
    pub ip: String,
    pub ok: bool,
    pub error: String,
}

/// Last result per node id, and what was last confirmed ("name ip") so an
/// unchanged node does not call the API again.
static STATUS: Mutex<Option<HashMap<i64, Status>>> = Mutex::new(None);
static RUN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub fn status(node_id: i64) -> Option<Status> {
    STATUS.lock().unwrap_or_else(|e| e.into_inner()).as_ref()?.get(&node_id).cloned()
}

fn set_status(node_id: i64, s: Option<Status>) {
    let mut g = STATUS.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    match s {
        Some(s) => {
            m.insert(node_id, s);
        }
        None => {
            m.remove(&node_id);
        }
    }
}

/// Runs a sync of every entry in the background.
pub fn spawn_sync(app: Arc<App>) {
    tokio::spawn(async move { sync_all(&app).await });
}

async fn sync_all(app: &App) {
    let _one = RUN.lock().await;
    let (token, wanted) = {
        let conn = app.db();
        let Ok(w) = db::load_world(&conn) else { return };
        let wanted: Vec<(i64, String, String)> = w
            .nodes
            .iter()
            .filter(|n| n.role == "entry")
            .map(|n| {
                let name = if n.anytls_on { n.anytls_sni.trim().trim_end_matches('.').to_ascii_lowercase() } else { String::new() };
                (n.id, name, n.address().to_string())
            })
            .collect();
        (w.cf_token, wanted)
    };
    for (id, name, addr) in wanted {
        // Only a real domain pointing at a known IP; a host set to a domain
        // is the user's own DNS and is left alone.
        let ip = addr.parse::<IpAddr>().ok().filter(public_ip);
        if token.is_empty() || name.is_empty() || name.parse::<IpAddr>().is_ok() || !name.contains('.') || ip.is_none() {
            set_status(id, None);
            continue;
        }
        let ip = ip.unwrap();
        if status(id).is_some_and(|s| s.ok && s.name == name && s.ip == ip.to_string()) {
            continue;
        }
        let result = upsert(&token, &name, ip).await;
        if let Err(e) = &result {
            eprintln!("dns: {name}: {e}");
        }
        set_status(id, Some(Status { name, ip: ip.to_string(), ok: result.is_ok(), error: result.err().unwrap_or_default() }));
    }
}

fn public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || (v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64)),
        IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80),
    }
}

async fn upsert(token: &str, name: &str, ip: IpAddr) -> Result<(), String> {
    let zone = find_zone(token, name).await?;
    let kind = if ip.is_ipv4() { "A" } else { "AAAA" };
    let found = call(token, "GET", &format!("/zones/{zone}/dns_records?type={kind}&name={name}"), None).await?;
    let record = json!({"type": kind, "name": name, "content": ip.to_string(), "ttl": 1, "proxied": false, "comment": "keel"});
    match found["result"].as_array().and_then(|a| a.first()) {
        Some(r) if r["content"] == ip.to_string() && r["proxied"] == false => Ok(()),
        // A record someone made by hand is theirs: only fix ones we made.
        Some(r) if r["comment"] != "keel" => Err(format!("{name} 已有一条手动建的记录指向 {}，没有改它", r["content"].as_str().unwrap_or("别处"))),
        Some(r) => {
            let rid = r["id"].as_str().unwrap_or_default();
            call(token, "PATCH", &format!("/zones/{zone}/dns_records/{rid}"), Some(record)).await.map(|_| ())
        }
        None => call(token, "POST", &format!("/zones/{zone}/dns_records"), Some(record)).await.map(|_| ()),
    }
}

/// The zone is the longest suffix of the name the token can see.
async fn find_zone(token: &str, name: &str) -> Result<String, String> {
    let labels: Vec<&str> = name.split('.').collect();
    for i in 0..labels.len().saturating_sub(1) {
        let candidate = labels[i..].join(".");
        let v = call(token, "GET", &format!("/zones?name={candidate}"), None).await?;
        if let Some(id) = v["result"].as_array().and_then(|a| a.first()).and_then(|z| z["id"].as_str()) {
            return Ok(id.to_string());
        }
    }
    Err(format!("Cloudflare 里没有 {name} 所在的域名（或令牌没有它的权限）"))
}

async fn call(token: &str, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
    let fut = request(token, method, path, body);
    let (status, v) = tokio::time::timeout(std::time::Duration::from_secs(20), fut).await.map_err(|_| "连接 Cloudflare 超时".to_string())??;
    if v["success"] == true {
        return Ok(v);
    }
    let msg = v["errors"]
        .as_array()
        .map(|a| a.iter().filter_map(|e| e["message"].as_str()).collect::<Vec<_>>().join("; "))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("HTTP {status}"));
    Err(format!("Cloudflare: {msg}"))
}

async fn request(token: &str, method: &str, path: &str, body: Option<Value>) -> Result<(u16, Value), String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let tcp = TcpStream::connect((API_HOST, 443)).await.map_err(|e| format!("连接 Cloudflare 失败：{e}"))?;
    let server = rustls::pki_types::ServerName::try_from(API_HOST).map_err(|e| e.to_string())?;
    let tls = TlsConnector::from(Arc::new(config)).connect(server, tcp).await.map_err(|e| format!("Cloudflare TLS：{e}"))?;
    let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let req = hyper::Request::builder()
        .method(method)
        .uri(format!("/client/v4{path}"))
        .header("host", API_HOST)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.map(|b| b.to_string()).unwrap_or_default())))
        .map_err(|e| e.to_string())?;
    let resp = send.send_request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
    let v = serde_json::from_slice(&bytes).map_err(|_| format!("Cloudflare 返回了看不懂的内容（HTTP {status}）"))?;
    Ok((status, v))
}
