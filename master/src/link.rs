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
            .map(parse_outbound)
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
    if let Some(rest) = link.strip_prefix("vless://") {
        parse_vless(rest)
    } else if let Some(rest) = link.strip_prefix("ss://") {
        parse_ss(rest)
    } else {
        Err(format!("只支持 vless:// 和 ss:// 链接：{}", short(link)))
    }
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
    let uuid = unescape(uuid);
    if uuid.is_empty() {
        return Err("vless 链接缺少 uuid".into());
    }
    Ok(Imported { name, kind: "vless", server, uuid, method: String::new(), password: String::new() })
}

fn check_plain_vless(network: &str, security: &str, flow: &str, encryption: &str, header: &str) -> Result<(), String> {
    if !matches!(network, "" | "tcp" | "raw") {
        return Err(format!("VLESS 暂时只支持 TCP，这条是 {network}"));
    }
    if !matches!(security, "" | "none") {
        return Err(format!("VLESS 暂时只支持不加密的明文 TCP（security=none），这条是 {security}"));
    }
    if !flow.is_empty() {
        return Err(format!("明文 TCP 的 VLESS 不能带 flow（{flow}）"));
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
    Ok(Imported { name, kind: "shadowsocks", server: host_port(&hostport, 0)?, uuid: String::new(), method, password })
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
            Ok(Imported { name, kind: "vless", server: address_port(srv)?, uuid, method: String::new(), password: String::new() })
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
            Ok(Imported { name, kind: "shadowsocks", server: address_port(srv)?, uuid: String::new(), method, password })
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
        let i = parse_link("ss://2022-blake3-aes-128-gcm:AbC+dEf/gHi%3D@192.0.2.1:20731#x").unwrap();
        assert_eq!(i.password, "AbC+dEf/gHi=");
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
          {"tag":"S","protocol":"shadowsocks","settings":{"servers":[{"address":"192.0.2.4","port":1,"method":"2022-blake3-aes-128-gcm","password":"k"}]}}]}"#;
        let v = parse_all(j).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].name.as_str(), v[0].server.as_str(), v[0].uuid.as_str()), ("K", "192.0.2.3:18888", "abc"));
        assert_eq!((v[1].kind, v[1].password.as_str()), ("shadowsocks", "k"));
        assert_eq!(parse_all("vless://a@h:1\n\nss://2022-blake3-aes-128-gcm:k@h:2").unwrap().len(), 2);
    }
}
