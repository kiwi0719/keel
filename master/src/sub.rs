//! Subscription links: one per user, listing every entry and protocol the
//! user may use, as a full config with split routing for the client asking.
//!
//! Every format carries the same plan: selectable groups (PROXY, 流媒体, AI and
//! one per Telegram DC location), each listing the entries; streaming, AI and
//! Telegram traffic sent to their groups, LAN and mainland
//! China direct, everything else PROXY. The format comes from `?format=` or
//! the User-Agent:
//!
//! - mihomo (Clash Meta, Clash Verge, FlClash, ...): YAML with DNS settings.
//! - Stash: the same YAML minus mihomo-only keys.
//! - sing-box (SFI / SFA / SFM): JSON for 1.12 and later.
//! - Surge: a managed profile; Surge has no VLESS, so AnyTLS entries only.
//! - anything else (v2rayN, NekoBox, Shadowrocket, Loon, ...): base64 share
//!   links, routing left to the client.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt::Write;
use std::sync::Arc;

use crate::api;
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
    // pin: otherwise, the master-made self-signed certificate clients pin
    // instead (PEM and SHA-256 of its DER).
    AnyTls { password: String, sni: String, verify: bool, pin: Option<(String, String)> },
    Reality { uuid: String, sni: String, public_key: String, short_id: String, fp: String },
}

impl Proxy {
    fn is_anytls(&self) -> bool {
        matches!(self.kind, Kind::AnyTls { .. })
    }
}

/// `trusted`: entries whose AnyTLS currently serves a CA-issued certificate.
fn proxies(user: &User, entries: &[&Node], trusted: &[i64]) -> Vec<Proxy> {
    let mut list = Vec::new();
    for n in entries {
        let server = n.address().to_string();
        if server.is_empty() {
            continue;
        }
        let (password, uuid) = user.credentials_for(n.id);
        let label = if n.name.is_empty() { n.code.clone() } else { n.name.clone() };
        // Both protocols on one entry get a suffix; a lone one keeps the
        // entry's own name.
        let both = n.vless_on && n.vless_port > 0 && n.anytls_on && n.anytls_port > 0;
        let named = |proto: &str| if both { format!("{label} · {proto}") } else { label.clone() };
        let verify = if n.anytls_acme { trusted.contains(&n.id) } else { !n.anytls_cert.is_empty() && !n.anytls_key.is_empty() };
        let pin = if verify || !n.anytls_self_signed() {
            None
        } else {
            crate::db::cert_sha256(&n.anytls_self_cert).map(|fp| (n.anytls_self_cert.clone(), fp))
        };
        // An entry whose certificate clients can neither verify nor pin (ACME
        // not issued yet) is left out rather than handed out unverified: the
        // AnyTLS password goes to whoever answers the connection.
        if n.anytls_on && n.anytls_port > 0 && (verify || pin.is_some()) {
            list.push(Proxy {
                name: named("AnyTLS"),
                kind: Kind::AnyTls {
                    password,
                    sni: n.anytls_sni.clone(),
                    verify,
                    pin,
                },
                server: server.clone(),
                port: if n.anytls_pub > 0 { n.anytls_pub } else { n.anytls_port },
            });
        }
        if n.vless_on && n.vless_port > 0 {
            list.push(Proxy {
                name: named("Reality"),
                kind: Kind::Reality {
                    uuid,
                    sni: n.reality_names().into_iter().next().unwrap_or_default(),
                    public_key: n.reality_public.clone(),
                    short_id: n.reality_short_ids().into_iter().next().unwrap_or_default(),
                    fp: if n.reality_fp.is_empty() { "chrome".into() } else { n.reality_fp.clone() },
                },
                server: server.clone(),
                port: if n.vless_pub > 0 { n.vless_pub } else { n.vless_port },
            });
        }
    }
    list
}

/// What every format renders.
struct Plan {
    proxies: Vec<Proxy>,
    /// This subscription's own URL, for Surge's managed profile.
    url: String,
}

const PROXY: &str = "PROXY";
const MEDIA: &str = "流媒体";
const AI: &str = "AI";

/// Telegram data centers by location, so each can pick its own entry: DC1
/// and DC3 in Miami, DC2 and DC4 in Amsterdam, DC5 in Singapore. Clients
/// dial these addresses directly, so plain IP rules catch them.
const TG: [(&str, &[&str]); 3] = [
    ("TG DC1/3 美国", &["149.154.172.0/22", "91.108.12.0/22", "2001:b28:f23d::/48"]),
    ("TG DC2/4 欧洲", &["149.154.160.0/21", "149.154.168.0/22", "91.108.4.0/22", "91.108.8.0/22", "2001:67c:4e8::/48", "2001:b28:f23c::/48"]),
    ("TG DC5 新加坡", &["91.108.56.0/22", "91.108.16.0/22", "2001:b28:f23f::/48"]),
];

/// Clash / Surge rule for one CIDR, without a DNS lookup.
fn cidr_rule(c: &str, group: &str) -> String {
    format!("{},{c},{group},no-resolve", if c.contains(':') { "IP-CIDR6" } else { "IP-CIDR" })
}

// Third-party rule lists, pinned to commits: a branch head would let
// whoever controls those repositories change, for every subscriber, what goes
// direct and past the proxy. Bump the commits deliberately to refresh them.
const BM: &str = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/0b6897dc17e0c513d25449c935a9694818e32f0c/rule";
const META_RULES: &str = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/74246501fd12b938b73482f406a6163d1e4a460f";
const SING_RULES: &str = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/608341f98813a26bcaa12ae19f017195a3274b2d";

const PRIVATE_V4: [&str; 6] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16"];
const PRIVATE_V6: [&str; 3] = ["::1/128", "fc00::/7", "fe80::/10"];

/// Selectable groups, each listing every entry and nothing else.
fn groups() -> impl Iterator<Item = &'static str> {
    [PROXY, MEDIA, AI].into_iter().chain(TG.iter().map(|(g, _)| *g))
}

// ---------- Clash family (mihomo, Stash) ----------

/// YAML scalar: JSON strings are valid YAML and take care of quoting.
fn q(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// (name, url) of the classical text rule sets the Clash formats load.
const CLASH_SETS: [(&str, &str); 4] = [
    ("GlobalMedia", "Clash/GlobalMedia/GlobalMedia.list"),
    ("YouTube", "Clash/YouTube/YouTube.list"),
    ("AI", ""),
    ("ChinaMax", "Clash/ChinaMax/ChinaMax.list"),
];

const MIHOMO_HEAD: &str = "mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
unified-delay: true
tcp-concurrent: true
geodata-mode: true
geo-auto-update: true
geo-update-interval: 24
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: [223.5.5.5, 119.29.29.29]
  nameserver: ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']
  proxy-server-nameserver: ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query']
  fallback: ['tls://1.1.1.1:853', 'tls://8.8.8.8:853']
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr: [240.0.0.0/4]
  fake-ip-filter: ['*.lan', '*.local', '*.arpa', 'localhost', 'time.*.com', 'ntp.*.com', '+.market.xiaomi.com', 'localhost.ptlogin2.qq.com', '*.msftncsi.com', 'www.msftconnecttest.com', 'challenges.cloudflare.com', '*.hcaptcha.com', '*.turnstile.com']
";

const STASH_HEAD: &str = "mode: rule
log-level: info
";

fn clash(plan: &Plan, stash: bool) -> String {
    let mut y = String::from(if stash { STASH_HEAD } else { MIHOMO_HEAD });
    y.push_str("proxies:\n");
    for p in &plan.proxies {
        let _ = write!(y, "  - name: {}\n    server: {}\n    port: {}\n    udp: true\n", q(&p.name), q(&p.server), p.port);
        match &p.kind {
            Kind::Reality { uuid, sni, public_key, short_id, fp } => {
                // mihomo reads servername, Stash sni; each ignores the other.
                let _ = write!(
                    y,
                    "    type: vless\n    uuid: {}\n    flow: xtls-rprx-vision\n    network: tcp\n    tls: true\n    servername: {}\n    sni: {}\n    client-fingerprint: {}\n    reality-opts:\n      public-key: {}\n      short-id: {}\n",
                    q(uuid), q(sni), q(sni), q(fp), q(public_key), q(short_id)
                );
            }
            Kind::AnyTls { password, sni, verify, pin } => {
                let _ = write!(y, "    type: anytls\n    password: {}\n    skip-cert-verify: false\n", q(password));
                if let (false, Some((_, fp))) = (verify, pin) {
                    let _ = writeln!(y, "    fingerprint: {}", q(fp));
                }
                if !sni.is_empty() {
                    let _ = writeln!(y, "    sni: {}", q(sni));
                }
            }
        }
    }
    let names: Vec<String> = plan.proxies.iter().map(|p| q(&p.name)).collect();
    let all = if names.is_empty() { "DIRECT".to_string() } else { names.join(", ") };
    y.push_str("proxy-groups:\n");
    for g in groups() {
        let _ = writeln!(y, "  - {{name: {}, type: select, proxies: [{all}]}}", q(g));
    }
    y.push_str("rule-providers:\n");
    for (name, path) in CLASH_SETS {
        let url = if path.is_empty() { format!("{META_RULES}/geo/geosite/classical/category-ai-%21cn.list") } else { format!("{BM}/{path}") };
        let _ = write!(y, "  {name}:\n    type: http\n    behavior: classical\n    format: text\n    url: {}\n    path: ./ruleset/{name}.list\n    interval: 86400\n", q(&url));
        // Fetch through the proxy: raw.githubusercontent.com is unreliable
        // from the mainland. Stash has no such option.
        if !stash {
            let _ = writeln!(y, "    proxy: {PROXY}");
        }
    }
    y.push_str("rules:\n");
    for (group, cidrs) in TG {
        for c in cidrs {
            let _ = writeln!(y, "  - {}", q(&cidr_rule(c, group)));
        }
    }
    let _ = write!(y, "  - RULE-SET,GlobalMedia,{MEDIA}\n  - RULE-SET,YouTube,{MEDIA}\n  - RULE-SET,AI,{AI}\n");
    for c in PRIVATE_V4 {
        let _ = writeln!(y, "  - IP-CIDR,{c},DIRECT,no-resolve");
    }
    for c in PRIVATE_V6 {
        let _ = writeln!(y, "  - IP-CIDR6,{c},DIRECT,no-resolve");
    }
    // no-resolve: a domain is not looked up just to test GEOIP, which would
    // send every foreign site the user visits to the domestic resolvers.
    // China domains are matched by ChinaMax above; GEOIP covers bare IPs.
    let _ = write!(y, "  - RULE-SET,ChinaMax,DIRECT\n  - GEOIP,CN,DIRECT,no-resolve\n  - MATCH,{PROXY}\n");
    y
}

// ---------- sing-box ----------

fn singbox(plan: &Plan) -> String {
    let mut outbounds: Vec<Value> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for p in &plan.proxies {
        names.push(p.name.clone());
        outbounds.push(match &p.kind {
            Kind::AnyTls { password, sni, verify, pin } => {
                let mut tls = json!({"enabled": true, "insecure": false});
                if let (false, Some((pem, _))) = (verify, pin) {
                    tls["certificate"] = json!(pem);
                }
                if !sni.is_empty() {
                    tls["server_name"] = json!(sni);
                }
                json!({"type": "anytls", "tag": p.name, "server": p.server, "server_port": p.port, "password": password, "tls": tls})
            }
            Kind::Reality { uuid, sni, public_key, short_id, fp } => json!({
                "type": "vless", "tag": p.name, "server": p.server, "server_port": p.port,
                "uuid": uuid, "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": true, "server_name": sni,
                    "utls": {"enabled": true, "fingerprint": fp},
                    "reality": {"enabled": true, "public_key": public_key, "short_id": short_id}
                }
            }),
        });
    }
    if names.is_empty() {
        names.push("direct".into());
    }
    for g in groups() {
        outbounds.push(json!({"type": "selector", "tag": g, "outbounds": names}));
    }
    outbounds.push(json!({"type": "direct", "tag": "direct"}));

    let set = |tag: &str, path: &str| {
        json!({"type": "remote", "tag": tag, "format": "binary", "url": format!("{SING_RULES}/geo/{path}.srs"), "download_detour": PROXY})
    };
    let mut rules = vec![
        json!({"action": "sniff"}),
        json!({"protocol": "dns", "action": "hijack-dns"}),
        json!({"ip_is_private": true, "outbound": "direct"}),
    ];
    for (group, cidrs) in TG {
        rules.push(json!({"ip_cidr": cidrs, "outbound": group}));
    }
    rules.push(json!({"rule_set": ["youtube", "media"], "outbound": MEDIA}));
    rules.push(json!({"rule_set": ["ai"], "outbound": AI}));
    rules.push(json!({"rule_set": ["cn", "cn-ip"], "outbound": "direct"}));

    let cfg = json!({
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {"type": "udp", "tag": "bootstrap", "server": "223.5.5.5"},
                {"type": "https", "tag": "ali", "server": "dns.alidns.com", "domain_resolver": "bootstrap"},
                {"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": PROXY}
            ],
            "rules": [{"rule_set": ["cn"], "server": "ali"}],
            "final": "remote"
        },
        "inbounds": [
            {"type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "auto_route": true, "strict_route": true},
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}
        ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "rule_set": [
                set("youtube", "geosite/youtube"),
                set("media", "geosite/category-entertainment"),
                set("ai", "geosite/category-ai-!cn"),
                set("cn", "geosite/cn"),
                set("cn-ip", "geoip/cn"),
            ],
            "final": PROXY,
            "auto_detect_interface": true,
            "default_domain_resolver": "ali"
        },
        "experimental": {"cache_file": {"enabled": true}}
    });
    serde_json::to_string_pretty(&cfg).unwrap_or_default()
}

// ---------- Surge ----------

/// Surge policy names cannot hold commas or equals signs.
fn surge_name(s: &str) -> String {
    s.replace([',', '='], " ")
}

fn surge(plan: &Plan) -> String {
    let list: Vec<&Proxy> = plan.proxies.iter().filter(|p| p.is_anytls()).collect();
    let mut s = format!(
        "#!MANAGED-CONFIG {} interval=43200 strict=false\n\n[General]\nloglevel = notify\ndns-server = 223.5.5.5, 119.29.29.29\nencrypted-dns-server = https://dns.alidns.com/dns-query\nskip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local\nexclude-simple-hostnames = true\n\n[Proxy]\n",
        plan.url
    );
    let mut names = Vec::new();
    for p in &list {
        if let Kind::AnyTls { password, sni, verify, pin } = &p.kind {
            let name = surge_name(&p.name);
            let _ = write!(s, "{name} = anytls, {}, {}, password=\"{}\"", p.server, p.port, password.replace('"', ""));
            if !sni.is_empty() {
                let _ = write!(s, ", sni={sni}");
            }
            if !verify {
                if let Some((_, fp)) = pin {
                    let _ = write!(s, ", server-cert-fingerprint-sha256={fp}");
                }
            }
            s.push('\n');
            names.push(name);
        }
    }
    let all = if names.is_empty() { "DIRECT".to_string() } else { names.join(", ") };
    s.push_str("\n[Proxy Group]\n");
    for g in groups() {
        let _ = writeln!(s, "{g} = select, {all}");
    }
    s.push_str("\n[Rule]\n");
    for (group, cidrs) in TG {
        for c in cidrs {
            let _ = writeln!(s, "{}", cidr_rule(c, group));
        }
    }
    let _ = writeln!(s, "RULE-SET,{BM}/Surge/GlobalMedia/GlobalMedia_All_No_Resolve.list,{MEDIA}");
    let _ = writeln!(s, "RULE-SET,{BM}/Surge/YouTube/YouTube.list,{MEDIA}");
    for set in ["OpenAI", "Claude", "Gemini", "Copilot"] {
        let _ = writeln!(s, "RULE-SET,{BM}/Surge/{set}/{set}.list,{AI}");
    }
    let _ = write!(s, "RULE-SET,LAN,DIRECT\nDOMAIN-SET,{BM}/Surge/ChinaMax/ChinaMax_Domain.list,DIRECT\nGEOIP,CN,DIRECT,no-resolve\nFINAL,{PROXY},dns-failed\n");
    s
}

// ---------- share links ----------

fn share_links(list: &[Proxy]) -> String {
    let mut out = Vec::new();
    // anytls:// links cannot pin a certificate: only entries clients can
    // verify are listed, never one marked insecure.
    for p in list.iter().filter(|p| !matches!(p.kind, Kind::AnyTls { verify: false, .. })) {
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
            Kind::AnyTls { password, sni, verify, .. } => {
                let sni = if sni.is_empty() { String::new() } else { format!("&sni={}", percent_encode(sni)) };
                let _ = verify;
                format!("anytls://{}@{host}:{}?insecure=0{sni}#{tag}", percent_encode(password), p.port)
            }
        });
    }
    STANDARD.encode(out.join("\n"))
}

// ---------- handler ----------

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Mihomo,
    Stash,
    SingBox,
    Surge,
    Links,
}

impl Format {
    fn parse(s: &str) -> Option<Format> {
        Some(match s {
            "clash" | "mihomo" | "meta" => Format::Mihomo,
            "stash" => Format::Stash,
            "singbox" | "sing-box" => Format::SingBox,
            "surge" => Format::Surge,
            "links" | "v2ray" | "base64" | "shadowrocket" => Format::Links,
            _ => return None,
        })
    }

    fn from_agent(ua: &str) -> Format {
        let has = |keys: &[&str]| keys.iter().any(|k| ua.contains(k));
        // Stash also says "clash", so it goes first.
        if has(&["stash"]) {
            Format::Stash
        } else if has(&["sing-box", "sfi/", "sfa/", "sfm/", "sft/"]) {
            Format::SingBox
        } else if has(&["surge"]) {
            Format::Surge
        } else if has(&["mihomo", "clash", "meta"]) {
            // Every Clash still maintained is mihomo underneath.
            Format::Mihomo
        } else {
            Format::Links
        }
    }
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
    // The database reads and the rendering run off the async workers.
    tokio::task::spawn_blocking(move || render(&app, &token, query, &headers))
        .await
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn render(app: &App, token: &str, query: SubQuery, headers: &HeaderMap) -> Response {
    let conn = app.db();
    let Some(user) = db::user_by_sub(&conn, token).ok().flatten() else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    // Only this user's entries and usage, not the whole world.
    let Ok(world) = db::load_user_world(&conn, &user) else {
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
    let format = query.format.as_deref().and_then(Format::parse).unwrap_or_else(|| Format::from_agent(&ua));
    let plan = Plan { proxies: list, url: format!("{}/s/{token}?format=surge", api::base_url(app, headers)) };

    let used = nodecfg::user_used(&world, &user, now());
    let mut info = format!("upload=0; download={used}; total={}", user.quota_bytes);
    if user.expire_at > 0 {
        let _ = write!(info, "; expire={}", user.expire_at);
    }
    let (ctype, ext, body) = match format {
        Format::Mihomo => ("text/yaml; charset=utf-8", ".yaml", clash(&plan, false)),
        Format::Stash => ("text/yaml; charset=utf-8", ".yaml", clash(&plan, true)),
        Format::SingBox => ("application/json; charset=utf-8", ".json", singbox(&plan)),
        Format::Surge => ("text/plain; charset=utf-8", ".conf", surge(&plan)),
        Format::Links => ("text/plain; charset=utf-8", "", share_links(&plan.proxies)),
    };
    let mut extra: HashMap<&str, String> = HashMap::new();
    extra.insert("subscription-userinfo", info);
    extra.insert("profile-update-interval", "12".into());
    extra.insert("content-disposition", format!("attachment; filename*=UTF-8''{}", percent_encode(&format!("keel-{}{ext}", user.name))));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        Plan {
            proxies: vec![
                Proxy {
                    name: "东京 · AnyTLS".into(),
                    kind: Kind::AnyTls { password: "pw".into(), sni: "a.example.com".into(), verify: true, pin: None },
                    server: "a.example.com".into(),
                    port: 443,
                },
                Proxy {
                    name: "东京 · Reality".into(),
                    kind: Kind::Reality {
                        uuid: "d0529668-8835-11ec-a8a3-0242ac120002".into(),
                        sni: "www.example.com".into(),
                        public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into(),
                        short_id: "0123abcd".into(),
                        fp: "chrome".into(),
                    },
                    server: "192.0.2.1".into(),
                    port: 8443,
                },
            ],
            url: "https://panel.example.com/s/t?format=surge".into(),
        }
    }

    #[test]
    fn agents() {
        assert!(Format::from_agent("stash/2.4.6 clash/1.9.0") == Format::Stash);
        assert!(Format::from_agent("clash-verge/v2.0.0") == Format::Mihomo);
        assert!(Format::from_agent("flclash/v0.8 clash.meta") == Format::Mihomo);
        assert!(Format::from_agent("sfi/1.12.0 (build 1; sing-box 1.12.0)") == Format::SingBox);
        assert!(Format::from_agent("surge ios/3245") == Format::Surge);
        assert!(Format::from_agent("shadowrocket/2070 cfnetwork") == Format::Links);
        assert!(Format::from_agent("v2rayn/7.0") == Format::Links);
    }

    #[test]
    fn surge_skips_vless() {
        let s = surge(&plan());
        assert!(s.contains("东京 · AnyTLS = anytls, a.example.com, 443"));
        assert!(!s.contains("Reality"));
    }

    #[test]
    fn empty_groups_fall_back_to_direct() {
        let p = Plan { proxies: Vec::new(), url: String::new() };
        assert!(clash(&p, false).contains("proxies: [DIRECT]"));
        assert!(surge(&p).contains("PROXY = select, DIRECT"));
        assert!(singbox(&p).contains("\"direct\""));
    }

    /// Writes sample configs for checking with the real clients:
    /// KEEL_SUB_SAMPLES=dir cargo test samples, then `mihomo -t -f`,
    /// `sing-box check -c`.
    #[test]
    fn samples() {
        let Ok(dir) = std::env::var("KEEL_SUB_SAMPLES") else { return };
        let p = plan();
        std::fs::write(format!("{dir}/mihomo.yaml"), clash(&p, false)).unwrap();
        std::fs::write(format!("{dir}/stash.yaml"), clash(&p, true)).unwrap();
        std::fs::write(format!("{dir}/sing-box.json"), singbox(&p)).unwrap();
        std::fs::write(format!("{dir}/surge.conf"), surge(&p)).unwrap();
        std::fs::write(format!("{dir}/links.txt"), share_links(&p.proxies)).unwrap();
    }
}
