//! Subscription links: one per user, listing every entry and protocol the
//! user may use. Clash-family clients (Stash, mihomo, Clash Verge) get YAML,
//! everything else a base64 list of share links (v2rayN, Shadowrocket, ...).

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;

use crate::app::App;
use crate::db::{self, Node, User};
use crate::nodecfg;
use crate::period::now;
use crate::util::percent_encode;

struct Proxy {
    name: String,
    kind: Kind,
    server: String,
    port: i64,
}

enum Kind {
    // verify: the entry uses a real certificate, so clients check it.
    AnyTls { password: String, sni: String, verify: bool },
    Reality { uuid: String, sni: String, public_key: String, short_id: String, fp: String },
}

/// `trusted`: entries whose AnyTLS currently serves a CA-issued certificate.
fn proxies(user: &User, entries: &[&Node], trusted: &[i64]) -> Vec<Proxy> {
    let mut list = Vec::new();
    for n in entries {
        let server = n.address().to_string();
        if server.is_empty() {
            continue;
        }
        let label = if n.name.is_empty() { n.code.clone() } else { n.name.clone() };
        if n.vless_on && n.vless_port > 0 {
            list.push(Proxy {
                name: format!("{label} · Reality"),
                kind: Kind::Reality {
                    uuid: user.uuid.clone(),
                    sni: n.reality_names().into_iter().next().unwrap_or_default(),
                    public_key: n.reality_public.clone(),
                    short_id: n.reality_short_ids().into_iter().next().unwrap_or_default(),
                    fp: if n.reality_fp.is_empty() { "chrome".into() } else { n.reality_fp.clone() },
                },
                server: server.clone(),
                port: if n.vless_pub > 0 { n.vless_pub } else { n.vless_port },
            });
        }
        if n.anytls_on && n.anytls_port > 0 {
            list.push(Proxy {
                name: format!("{label} · AnyTLS"),
                kind: Kind::AnyTls {
                    password: user.anytls_password.clone(),
                    sni: n.anytls_sni.clone(),
                    verify: if n.anytls_acme { trusted.contains(&n.id) } else { !n.anytls_cert.is_empty() && !n.anytls_key.is_empty() },
                },
                server: server.clone(),
                port: if n.anytls_pub > 0 { n.anytls_pub } else { n.anytls_port },
            });
        }
    }
    list
}

/// YAML scalar: JSON strings are valid YAML and take care of quoting.
fn q(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

fn clash(list: &[Proxy]) -> String {
    let mut y = String::from("mixed-port: 7890\nmode: rule\nproxies:\n");
    for p in list {
        let _ = write!(y, "  - name: {}\n    server: {}\n    port: {}\n    udp: true\n", q(&p.name), q(&p.server), p.port);
        match &p.kind {
            Kind::Reality { uuid, sni, public_key, short_id, fp } => {
                let _ = write!(
                    y,
                    "    type: vless\n    uuid: {}\n    flow: xtls-rprx-vision\n    network: tcp\n    tls: true\n    servername: {}\n    client-fingerprint: {}\n    reality-opts:\n      public-key: {}\n      short-id: {}\n",
                    q(uuid), q(sni), q(fp), q(public_key), q(short_id)
                );
            }
            Kind::AnyTls { password, sni, verify } => {
                let _ = write!(y, "    type: anytls\n    password: {}\n    skip-cert-verify: {}\n", q(password), !verify);
                if !sni.is_empty() {
                    let _ = writeln!(y, "    sni: {}", q(sni));
                }
            }
        }
    }
    let names: Vec<String> = list.iter().map(|p| q(&p.name)).collect();
    let _ = write!(
        y,
        "proxy-groups:\n  - name: keel\n    type: select\n    proxies: [{}]\nrules:\n  - GEOIP,LAN,DIRECT\n  - GEOIP,CN,DIRECT\n  - MATCH,keel\n",
        names.join(", ")
    );
    y
}

fn share_links(list: &[Proxy]) -> String {
    let mut out = Vec::new();
    for p in list {
        let host = if p.server.contains(':') { format!("[{}]", p.server) } else { p.server.clone() };
        let tag = percent_encode(&p.name);
        out.push(match &p.kind {
            Kind::Reality { uuid, sni, public_key, short_id, fp } => format!(
                "vless://{uuid}@{host}:{}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={}&fp={}&pbk={}&sid={}&type=tcp#{tag}",
                p.port,
                percent_encode(sni),
                percent_encode(fp),
                percent_encode(public_key),
                percent_encode(short_id)
            ),
            Kind::AnyTls { password, sni, verify } => {
                let sni = if sni.is_empty() { String::new() } else { format!("&sni={}", percent_encode(sni)) };
                format!("anytls://{}@{host}:{}?insecure={}{sni}#{tag}", percent_encode(password), p.port, if *verify { 0 } else { 1 })
            }
        });
    }
    STANDARD.encode(out.join("\n"))
}

#[derive(Deserialize)]
pub struct SubQuery {
    format: Option<String>,
}

pub async fn subscription(
    State(app): State<Arc<App>>,
    Path(token): Path<String>,
    Query(query): Query<SubQuery>,
    headers: HeaderMap,
) -> Response {
    let conn = app.db();
    let Some(user) = db::user_by_sub(&conn, &token).ok().flatten() else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let Ok(world) = db::load_world(&conn) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    drop(conn);
    let allowed = world.user_entries.get(&user.id).cloned().unwrap_or_default();
    let entries: Vec<&Node> = world.nodes.iter().filter(|n| n.is_entry() && allowed.contains(&n.id)).collect();
    // An ACME cert counts only once the node reports it issued, so clients
    // do not start verifying against the interim self-signed one.
    let trusted: Vec<i64> = {
        let live = app.live();
        entries
            .iter()
            .filter(|n| n.anytls_acme)
            .filter(|n| {
                live.nodes.get(&n.id).is_some_and(|l| l.certs.iter().any(|c| c.domain == n.anytls_sni && c.issuer == "acme" && c.not_after > now()))
            })
            .map(|n| n.id)
            .collect()
    };
    let list = if user.enabled { proxies(&user, &entries, &trusted) } else { Vec::new() };

    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    let format = query.format.unwrap_or_else(|| {
        if ["clash", "stash", "mihomo", "meta"].iter().any(|k| ua.contains(k)) {
            "clash".into()
        } else {
            "links".into()
        }
    });
    let used = nodecfg::user_used(&world, &user, now());
    let mut info = format!("upload=0; download={used}; total={}", user.quota_bytes);
    if user.expire_at > 0 {
        let _ = write!(info, "; expire={}", user.expire_at);
    }
    let mut extra: HashMap<&str, String> = HashMap::new();
    extra.insert("subscription-userinfo", info);
    extra.insert("profile-update-interval", "12".into());
    extra.insert("content-disposition", format!("attachment; filename*=UTF-8''{}", percent_encode(&format!("keel-{}", user.name))));
    let (ctype, body) = if format == "clash" {
        ("text/yaml; charset=utf-8", clash(&list))
    } else {
        ("text/plain; charset=utf-8", share_links(&list))
    };
    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, ctype.parse().expect("content type"));
    h.insert(header::CACHE_CONTROL, "no-store".parse().expect("cache control"));
    for (k, v) in extra {
        if let Ok(v) = v.parse() {
            h.insert(k, v);
        }
    }
    resp
}
