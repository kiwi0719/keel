//! Imports third-party servers as external exits, the way 3x-ui's outbound
//! "import link" does: vless:// and ss:// share links, or an Xray outbound
//! JSON object. Only what keel-node can dial is accepted: VLESS over plain
//! TCP (no TLS, no flow) and Shadowsocks AEAD / 2022 without plugins.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;

#[derive(Debug, PartialEq)]
pub struct Imported {
    /// The link's remark (after #) or the outbound's tag; may be empty.
    pub name: String,
    /// "vless" or "shadowsocks".
    pub kind: &'static str,
    /// host:port, IPv6 hosts in brackets.
    pub server: String,
    pub uuid: String,
    pub method: String,
    pub password: String,
    /// VLESS over TLS: the name the server's certificate must carry; empty
    /// for plain TCP.
    pub tls_sni: String,
    /// VLESS: flow and REALITY settings as the node config's JSON
    /// ({"flow":..,"reality":{..}}), or empty.
    pub vless_opts: String,
}

pub const SS_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
];

/// Parses every non-empty line of text, or the whole text when it is JSON.
pub fn parse_all(text: &str) -> Result<Vec<Imported>, String> {
    let text = text.trim();
    if text.starts_with('{') || text.starts_with('[') {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("JSON 看不懂：{e}"))?;
        let items = match v {
            Value::Array(a) => a,
            // A whole Xray config: take its outbounds.
            Value::Object(ref o) if o.get("outbounds").is_some_and(Value::is_array) => o["outbounds"].as_array().cloned().unwrap_or_default(),
            other => vec![other],
        };
        let out: Vec<Imported> = items
            .iter()
            .filter(|o| matches!(o["protocol"].as_str(), Some("vless" | "shadowsocks")))
            .map(|o| parse_outbound(o).and_then(checked))
            .collect::<Result<_, _>>()?;
        if out.is_empty() {
            return Err("JSON 里没有 vless 或 shadowsocks 出站".into());
        }
        return Ok(out);
    }
    let out: Vec<Imported> = text.lines().map(str::trim).filter(|l| !l.is_empty()).map(parse_link).collect::<Result<_, _>>()?;
    if out.is_empty() {
        return Err("没有可导入的链接".into());
    }
    Ok(out)
}

pub fn parse_link(link: &str) -> Result<Imported, String> {
    let i = if let Some(rest) = link.strip_prefix("vless://") {
        parse_vless(rest)
    } else if let Some(rest) = link.strip_prefix("ss://") {
        parse_ss(rest)
    } else {
        Err(format!("只支持 vless:// 和 ss:// 链接：{}", short(link)))
    }?;
    checked(i)
}

/// Checks what a third party wrote before it reaches nodes, subscriptions,
/// the panel and the node's terminal: no control or direction-changing
/// characters, no server on a loopback, private or link-local address
/// (entries would send users' traffic to their own LAN), and SS-2022 keys of
/// the right size (a bad one makes every entry routed to it reject configs).
fn checked(mut i: Imported) -> Result<Imported, String> {
    let hidden = |c: char| c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{feff}');
    i.name = i.name.chars().filter(|c| !hidden(*c)).take(40).collect::<String>().trim().to_string();
    if i.server.chars().any(hidden) {
        return Err(format!("地址里有控制字符：{}", short(&i.server.escape_debug().to_string())));
    }
    let host = i.server.rsplit_once(':').map_or(i.server.as_str(), |(h, _)| h).trim_matches(|c| c == '[' || c == ']');
    let local = host.eq_ignore_ascii_case("localhost")
        || host.to_ascii_lowercase().ends_with(".localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|ip| !crate::dns::public_ip(&ip.to_canonical()));
    if local {
        return Err(format!("出口地址不能是本机或内网地址：{}", short(&i.server)));
    }
    if let Some(bits) = i.method.strip_prefix("2022-blake3-") {
        let size = if bits.starts_with("aes-128") { 16 } else { 32 };
        let ok = !i.password.is_empty()
            && i.password.split(':').all(|k| base64::engine::general_purpose::STANDARD.decode(k).is_ok_and(|b| b.len() == size));
        if !ok {
            return Err(format!("{} 的密钥应是 {size} 字节的 base64", i.method));
        }
    }
    Ok(i)
}

/// Splits "body?query#remark" into its parts, the remark percent-decoded.
fn split_link(s: &str) -> (&str, Vec<(String, String)>, String) {
    let (s, remark) = match s.split_once('#') {
        Some((a, b)) => (a, unescape(b)),
        None => (s, String::new()),
    };
    let (body, query) = match s.split_once('?') {
        Some((a, b)) => (a, b),
        None => (s, ""),
    };
    let query = query
        .split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k.to_string(), unescape(v))
        })
        .collect();
    (body.trim_end_matches('/'), query, remark.trim().to_string())
}

fn param<'a>(q: &'a [(String, String)], key: &str) -> &'a str {
    q.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or("")
}

fn parse_vless(rest: &str) -> Result<Imported, String> {
    let (body, q, name) = split_link(rest);
    let (uuid, hostport) = body.rsplit_once('@').ok_or("vless 链接缺少 uuid@地址")?;
    let server = host_port(hostport, 443)?;
    check_plain_vless(param(&q, "type"), param(&q, "security"), param(&q, "flow"), param(&q, "encryption"), param(&q, "headerType"))?;
    let vless_opts = vless_options(param(&q, "security"), param(&q, "flow"), param(&q, "sni"), param(&q, "pbk"), param(&q, "sid"), param(&q, "fp"))?;
    if matches!(param(&q, "allowInsecure"), "1" | "true") || matches!(param(&q, "insecure"), "1" | "true") {
        return Err("不接受跳过证书校验的 VLESS（allowInsecure）".into());
    }
    let tls_sni = if param(&q, "security") == "tls" {
        let sni = param(&q, "sni");
        if sni.is_empty() { server_host(&server) } else { sni.to_string() }
    } else {
        String::new()
    };
    let uuid = unescape(uuid);
    if uuid.is_empty() {
        return Err("vless 链接缺少 uuid".into());
    }
    Ok(Imported { name, kind: "vless", server, uuid, method: String::new(), password: String::new(), tls_sni, vless_opts })
}

/// The flow and REALITY part of a VLESS outbound, as JSON for the node.
fn vless_options(security: &str, flow: &str, sni: &str, pbk: &str, sid: &str, fp: &str) -> Result<String, String> {
    let mut o = serde_json::Map::new();
    if !flow.is_empty() {
        o.insert("flow".into(), Value::String(flow.into()));
    }
    if security == "reality" {
        let key = URL_SAFE_NO_PAD.decode(pbk.trim_end_matches('='));
        if !key.is_ok_and(|k| k.len() == 32) {
            return Err("Reality 链接的公钥（pbk）不对".into());
        }
        if sni.is_empty() {
            return Err("Reality 链接缺少 sni".into());
        }
        if sid.len() > 16 || sid.len() % 2 != 0 || !sid.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Reality 链接的 shortId（sid）不对".into());
        }
        let fp = if matches!(fp, "chrome" | "firefox" | "safari" | "ios" | "edge") { fp } else { "chrome" };
        o.insert("reality".into(), serde_json::json!({"server_name": sni, "public_key": pbk, "short_id": sid, "fingerprint": fp}));
    }
    Ok(if o.is_empty() { String::new() } else { Value::Object(o).to_string() })
}

fn check_plain_vless(network: &str, security: &str, flow: &str, encryption: &str, header: &str) -> Result<(), String> {
    if !matches!(network, "" | "tcp" | "raw") {
        return Err(format!("VLESS 暂时只支持 TCP，这条是 {network}"));
    }
    if !matches!(security, "" | "none" | "tls" | "reality") {
        return Err(format!("VLESS 只支持 TCP 明文、TLS 或 Reality，这条是 {security}"));
    }
    if !matches!(flow, "" | "xtls-rprx-vision") {
        return Err(format!("不支持 VLESS flow {flow}"));
    }
    if !flow.is_empty() && !matches!(security, "tls" | "reality") {
        return Err("flow 要配合 TLS 或 Reality".into());
    }
    if !matches!(encryption, "" | "none") {
        return Err(format!("不支持 VLESS encryption={encryption}"));
    }
    if !matches!(header, "" | "none") {
        return Err(format!("不支持 TCP 伪装头 {header}"));
    }
    Ok(())
}

fn parse_ss(rest: &str) -> Result<Imported, String> {
    let (body, q, name) = split_link(rest);
    if !param(&q, "plugin").is_empty() {
        return Err("不支持带插件的 SS 链接（plugin=...）".into());
    }
    let (userinfo, hostport) = match body.rsplit_once('@') {
        Some((u, h)) => (decode_userinfo(u), h.to_string()),
        // Legacy: the whole method:password@host:port is base64.
        None => {
            let plain = b64(body).ok_or("SS 链接看不懂")?;
            let (u, h) = plain.rsplit_once('@').ok_or("SS 链接缺少 @地址")?;
            (u.to_string(), h.to_string())
        }
    };
    let (method, password) = match userinfo.split_once(':') {
        Some((m, p)) => (m.to_lowercase(), p.to_string()),
        None => ("2022-blake3-aes-128-gcm".to_string(), userinfo.clone()),
    };
    if !SS_METHODS.contains(&method.as_str()) {
        return Err(format!("不支持的 SS 加密方式 {method}"));
    }
    if password.is_empty() {
        return Err("SS 链接缺少密码".into());
    }
    Ok(Imported { name, kind: "shadowsocks", server: host_port(&hostport, 0)?, uuid: String::new(), method, password, tls_sni: String::new(), vless_opts: String::new() })
}

/// SIP002 userinfo is base64(method:password); SIP022 allows it
/// percent-encoded in the clear (2022 keys are base64 themselves, so try the
/// clear form first when it already has a known method).
fn decode_userinfo(u: &str) -> String {
    let clear = unescape(u);
    if let Some((m, _)) = clear.split_once(':') {
        if SS_METHODS.contains(&m.to_lowercase().as_str()) {
            return clear;
        }
    }
    b64(u).filter(|s| s.contains(':')).unwrap_or(clear)
}

fn parse_outbound(o: &Value) -> Result<Imported, String> {
    let name = o["tag"].as_str().unwrap_or("").to_string();
    let s = &o["settings"];
    let stream = &o["streamSettings"];
    let address_port = |v: &Value| -> Result<String, String> {
        let host = v["address"].as_str().ok_or("出站缺少 address")?;
        let port = v["port"].as_u64().ok_or("出站缺少 port")?;
        host_port(&format!("{}:{port}", bracket(host)), 0)
    };
    match o["protocol"].as_str() {
        Some("vless") => {
            // Old shape settings.vnext[0].users[0], newer flat settings.
            let (srv, user) = match s["vnext"].get(0) {
                Some(v) => (v, &v["users"][0]),
                None => (s, s),
            };
            check_plain_vless(
                stream["network"].as_str().unwrap_or(""),
                stream["security"].as_str().unwrap_or(""),
                user["flow"].as_str().unwrap_or(""),
                user["encryption"].as_str().unwrap_or(""),
                stream["tcpSettings"]["header"]["type"].as_str().or(stream["rawSettings"]["header"]["type"].as_str()).unwrap_or(""),
            )?;
            let uuid = user["id"].as_str().unwrap_or("").to_string();
            if uuid.is_empty() {
                return Err("vless 出站缺少 id".into());
            }
            let tls = &stream["tlsSettings"];
            if tls["allowInsecure"].as_bool() == Some(true) {
                return Err("不接受跳过证书校验的 VLESS（allowInsecure）".into());
            }
            let server = address_port(srv)?;
            let tls_sni = if stream["security"].as_str() == Some("tls") {
                tls["serverName"].as_str().filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| server_host(&server))
            } else {
                String::new()
            };
            let rs = &stream["realitySettings"];
            let vless_opts = vless_options(
                stream["security"].as_str().unwrap_or(""),
                user["flow"].as_str().unwrap_or(""),
                rs["serverName"].as_str().unwrap_or(""),
                rs["publicKey"].as_str().or(rs["password"].as_str()).unwrap_or(""),
                rs["shortId"].as_str().unwrap_or(""),
                rs["fingerprint"].as_str().unwrap_or(""),
            )?;
            Ok(Imported { name, kind: "vless", server, uuid, method: String::new(), password: String::new(), tls_sni, vless_opts })
        }
        _ => {
            let srv = s["servers"].get(0).unwrap_or(s);
            let method = srv["method"].as_str().unwrap_or("").to_lowercase();
            if !SS_METHODS.contains(&method.as_str()) {
                return Err(format!("不支持的 SS 加密方式 {method}"));
            }
            if !matches!(stream["security"].as_str().unwrap_or(""), "" | "none") {
                return Err("不支持套了 TLS 的 SS 出站".into());
            }
            let password = srv["password"].as_str().unwrap_or("").to_string();
            if password.is_empty() {
                return Err("SS 出站缺少密码".into());
            }
            Ok(Imported { name, kind: "shadowsocks", server: address_port(srv)?, uuid: String::new(), method, password, tls_sni: String::new(), vless_opts: String::new() })
        }
    }
}

/// Normalizes "host:port" / "[v6]:port"; default_port 0 means required.
fn host_port(s: &str, default_port: u16) -> Result<String, String> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once(']').ok_or("IPv6 地址少了 ]")?;
        (h, p.strip_prefix(':').unwrap_or(""))
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => (h, p),
            None => (s, ""),
        }
    };
    if host.is_empty() || host.contains(|c: char| c.is_whitespace() || c == '/' || c == '@') {
        return Err(format!("地址不对：{}", short(s)));
    }
    let port: u16 = if port.is_empty() && default_port != 0 {
        default_port
    } else {
        port.parse().ok().filter(|p| *p > 0).ok_or_else(|| format!("端口不对：{}", short(s)))?
    };
    Ok(format!("{}:{port}", bracket(host)))
}

/// The host part of host:port, without IPv6 brackets.
fn server_host(server: &str) -> String {
    server.rsplit_once(':').map_or(server, |(h, _)| h).trim_matches(|c| c == '[' || c == ']').to_string()
}

fn bracket(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn b64(s: &str) -> Option<String> {
    let s = unescape(s);
    let s = s.trim();
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|e| e.decode(s).ok())
        .and_then(|b| String::from_utf8(b).ok())
}

/// Percent-decoding; unlike form decoding, '+' stays '+' (2022 keys contain it).
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn short(s: &str) -> String {
    s.chars().take(40).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_link() {
        let i = parse_link("vless://0f8b7a52-1111-4222-8333-444455556666@example.com:26096?type=tcp&security=none&encryption=none#%F0%9F%87%AF%F0%9F%87%B5GLBB").unwrap();
        assert_eq!(i.kind, "vless");
        assert_eq!(i.server, "example.com:26096");
        assert_eq!(i.uuid, "0f8b7a52-1111-4222-8333-444455556666");
        assert_eq!(i.name, "🇯🇵GLBB");
        assert!(parse_link("vless://u@h:1?security=reality&flow=xtls-rprx-vision").is_err());
        // VLESS over TLS keeps the certificate name; skipping verification is refused
        let i = parse_link("vless://abc@192.0.2.9:443?security=tls&sni=v.example.com&type=tcp#t").unwrap();
        assert_eq!(i.tls_sni, "v.example.com");
        assert_eq!(parse_link("vless://abc@v.example.net:443?security=tls").unwrap().tls_sni, "v.example.net");
        assert!(parse_link("vless://abc@192.0.2.9:443?security=tls&allowInsecure=1").is_err());
        assert_eq!(parse_link("vless://abc@192.0.2.9:443?security=none").unwrap().tls_sni, "");
        // VLESS + Reality + Vision: settings carried to the node config
        let pbk = "SYIxGG0Hl1PQSQEXjLdHq0YozuSUH3SkgFVnaDzNP3c";
        let i = parse_link(&format!("vless://abc@192.0.2.9:443?security=reality&sni=www.microsoft.com&pbk={pbk}&sid=0123abcd&fp=firefox&flow=xtls-rprx-vision&type=tcp#r")).unwrap();
        let o: Value = serde_json::from_str(&i.vless_opts).unwrap();
        assert_eq!((o["flow"].as_str(), o["reality"]["public_key"].as_str(), o["reality"]["short_id"].as_str(), o["reality"]["fingerprint"].as_str()), (Some("xtls-rprx-vision"), Some(pbk), Some("0123abcd"), Some("firefox")));
        assert!(parse_link("vless://abc@192.0.2.9:443?security=reality&sni=a.com&pbk=short").is_err());
        assert!(parse_link(&format!("vless://abc@192.0.2.9:443?security=reality&pbk={pbk}")).is_err());
        assert!(parse_link("vless://abc@192.0.2.9:443?flow=xtls-rprx-vision").is_err());
        assert!(parse_link("vless://u@h:1?type=ws").is_err());
        assert_eq!(parse_link("vless://u@[2001:db8::1]:8443").unwrap().server, "[2001:db8::1]:8443");
    }

    #[test]
    fn ss_links() {
        // SIP002 base64 userinfo
        let u = STANDARD.encode("aes-256-gcm:pa+ss");
        let i = parse_link(&format!("ss://{u}@192.0.2.1:8388#A%20B")).unwrap();
        assert_eq!((i.kind, i.method.as_str(), i.password.as_str(), i.server.as_str(), i.name.as_str()), ("shadowsocks", "aes-256-gcm", "pa+ss", "192.0.2.1:8388", "A B"));
        // SIP022 clear userinfo with a '+' in the key
        let i = parse_link("ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAA+w%3D%3D@192.0.2.1:20731#x").unwrap();
        assert_eq!(i.password, "AAAAAAAAAAAAAAAAAAAA+w==");
        // a key of the wrong size, a private server, control characters
        assert!(parse_link("ss://2022-blake3-aes-128-gcm:AbC+dEf/gHi%3D@192.0.2.1:20731#x").is_err());
        assert!(parse_link("ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAA+w%3D%3D@127.0.0.1:20731").is_err());
        assert!(parse_link("ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAA+w%3D%3D@169.254.169.254:80").is_err());
        assert!(parse_link("ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAA+w%3D%3D@[::ffff:10.0.0.1]:80").is_err());
        let i = parse_link("ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAA+w%3D%3D@192.0.2.1:1#a%1B%5B2Jb%E2%80%AEc").unwrap();
        assert_eq!(i.name, "a[2Jbc");
        // legacy all-base64
        let all = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:pw@192.0.2.2:443");
        let i = parse_link(&format!("ss://{all}#old")).unwrap();
        assert_eq!((i.method.as_str(), i.server.as_str()), ("chacha20-ietf-poly1305", "192.0.2.2:443"));
        assert!(parse_link("ss://YWVzLTEyOC1nY206cHc@h:1?plugin=obfs-local").is_err());
        assert!(parse_link(&format!("ss://{}@h:1", STANDARD.encode("rc4-md5:pw"))).is_err());
    }

    #[test]
    fn xray_json() {
        let j = r#"{"outbounds":[
          {"tag":"direct","protocol":"freedom"},
          {"tag":"K","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.3","port":18888,"users":[{"id":"abc","encryption":"none","flow":""}]}]},"streamSettings":{"network":"tcp","security":"none"}},
          {"tag":"S","protocol":"shadowsocks","settings":{"servers":[{"address":"192.0.2.4","port":1,"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA=="}]}}]}"#;
        let v = parse_all(j).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].name.as_str(), v[0].server.as_str(), v[0].uuid.as_str()), ("K", "192.0.2.3:18888", "abc"));
        assert_eq!((v[1].kind, v[1].password.as_str()), ("shadowsocks", "AAAAAAAAAAAAAAAAAAAAAA=="));
        assert_eq!(parse_all("vless://a@h:1\n\nss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@h:2").unwrap().len(), 2);
    }
}
