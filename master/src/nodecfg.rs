//! Builds the config each node runs, in keel-node's own JSON format
//! (examples/entry.json, examples/exit.json), from the panel's data.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::db::{Exit, Node, User, World};
use crate::period::period_label;
use crate::util::exit_key;

pub const SS_METHOD: &str = "2022-blake3-aes-128-gcm";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeTarget {
    pub name: String,
    pub label: String,
    pub host: String,
}

/// Shanghai targets from Zstatic's public TCPing list
/// (https://china-tcping-list.vercel.app/): one domain per carrier whose
/// address is kept current upstream, so nothing here goes stale. Port 80;
/// they answer TCP only, not ICMP.
pub fn default_probe_targets() -> Vec<ProbeTarget> {
    [("ct", "电信"), ("cu", "联通"), ("cm", "移动")]
        .iter()
        .map(|(n, l)| ProbeTarget {
            name: n.to_string(),
            label: l.to_string(),
            host: format!("sh-{n}-v4.ip.zstaticcdn.com:80"),
        })
        .collect()
}

pub fn user_counter(user: i64) -> String {
    format!("u{user}")
}

pub fn exit_counter(entry: i64, exit: i64) -> String {
    format!("n{entry}x{exit}")
}

/// The exit id an exit-node counter name belongs to.
pub fn counter_exit(name: &str) -> Option<i64> {
    let rest = name.strip_prefix('n')?;
    let (entry, exit) = rest.split_once('x')?;
    entry.parse::<i64>().ok()?;
    exit.parse().ok()
}

pub fn user_period(w: &World, u: &User, now: i64) -> String {
    let base = period_label(now, w.tz, u.reset_day as u32, 0);
    if u.reset_seq > 0 && u.reset_period == base {
        format!("{base}#{}", u.reset_seq)
    } else {
        base
    }
}

pub fn user_used(w: &World, u: &User, now: i64) -> i64 {
    w.used(&user_counter(u.id), &user_period(w, u, now), None)
}

pub fn exit_period(w: &World, e: &Exit, now: i64) -> String {
    period_label(now, w.tz, e.reset_day as u32, 0)
}

pub fn exit_used(w: &World, e: &Exit, now: i64) -> i64 {
    let period = exit_period(w, e, now);
    w.usage
        .iter()
        .filter(|((n, name, p), _)| *n == e.node_id && *p == period && counter_exit(name) == Some(e.id))
        .map(|(_, v)| *v)
        .sum()
}

fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// How the node proves the domain: Cloudflare DNS when a token is set (works
/// behind NAT), else TLS-ALPN on the AnyTLS listener when clients reach it on
/// 443, else a temporary HTTP listener on :80.
fn acme(w: &World, node: &Node) -> Value {
    let public = if node.anytls_pub > 0 { node.anytls_pub } else { node.anytls_port };
    let mut a = if !w.cf_token.is_empty() {
        json!({"challenge": "dns", "dns_provider": "cloudflare", "dns_token": w.cf_token})
    } else if public == 443 {
        json!({"challenge": "tls-alpn"})
    } else {
        json!({"challenge": "http"})
    };
    if !w.acme_email.is_empty() {
        a["email"] = json!(w.acme_email);
    }
    a
}

fn listen(port: i64) -> String {
    format!(":{port}")
}

/// The outbound tag for an exit, or None if entries cannot reach it yet
/// (its node has no known address).
fn exit_tag(w: &World, exit_id: i64) -> Option<String> {
    let e = w.exit(exit_id)?;
    let reachable = if e.is_external() { !e.server.is_empty() } else { !w.node(e.node_id)?.address().is_empty() };
    reachable.then(|| format!("x{exit_id}"))
}

pub fn build(w: &World, node: &Node, secret: &str, probes: &[ProbeTarget], now: i64) -> Value {
    let mut config = if node.is_entry() { entry(w, node, secret, now) } else { exit(w, node, secret, now) };
    let probes: Vec<Value> = probes
        .iter()
        .filter(|p| !p.host.is_empty())
        .map(|p| json!({"name": p.name, "host": p.host}))
        .collect();
    if !probes.is_empty() {
        config["probes"] = Value::Array(probes);
    }
    config
}

/// The outbound for a primary exit plus ordered fallbacks (0 = direct): a
/// tag, or a list when there is more than one, which keel-node walks in
/// order skipping exits its health check marks dead.
fn outbound_choice(w: &World, primary: i64, fallback: &[i64], used: &mut Vec<i64>) -> Option<Value> {
    let mut tags: Vec<String> = Vec::new();
    for id in std::iter::once(&primary).chain(fallback) {
        let tag = if *id == 0 {
            "direct".to_string()
        } else {
            match exit_tag(w, *id) {
                Some(t) => {
                    used.push(*id);
                    t
                }
                None => continue,
            }
        };
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    match tags.len() {
        0 => None,
        1 => Some(json!(tags[0])),
        _ => Some(json!(tags)),
    }
}

fn entry(w: &World, node: &Node, secret: &str, now: i64) -> Value {
    let mut rules = Vec::new();
    let direct = lines(&node.direct_list);
    if !direct.is_empty() {
        rules.push(json!({"name": "direct", "domains": direct, "outbound": "direct"}));
    }
    let mut used_exits = Vec::new();
    for r in w.rules_of(node.id) {
        // Unreachable exits are left out; a rule with none left is dropped so
        // its traffic follows the default instead of failing validation.
        let Some(outbound) = outbound_choice(w, r.exit_id, &r.fallback, &mut used_exits) else { continue };
        let Some(set) = w.rulesets.iter().find(|s| s.id == r.ruleset) else { continue };
        rules.push(json!({"name": set.id, "domains": lines(&set.domains), "outbound": outbound}));
    }
    let mut route = json!({"ipv4_only": node.ipv4_only});
    if !rules.is_empty() {
        route["rules"] = Value::Array(rules);
    }
    if node.default_exit != 0 || !node.default_fallback.is_empty() {
        if let Some(choice) = outbound_choice(w, node.default_exit, &node.default_fallback, &mut used_exits) {
            route["final"] = choice;
        }
    }
    used_exits.sort_unstable();
    used_exits.dedup();
    let outbounds: Vec<Value> = used_exits
        .iter()
        .filter_map(|id| {
            let e = w.exit(*id)?;
            match e.kind.as_str() {
                "vless" => return Some(json!({"tag": format!("x{id}"), "type": "vless", "server": e.server, "uuid": e.uuid})),
                "shadowsocks" => {
                    return Some(json!({"tag": format!("x{id}"), "type": "ss2022", "server": e.server, "method": e.method, "password": e.psk}))
                }
                _ => {}
            }
            let n = w.node(e.node_id)?;
            let mut o = json!({
                "tag": format!("x{id}"),
                "type": "ss2022",
                "server": format!("{}:{}", n.address(), e.public_port()),
                "method": SS_METHOD,
                "password": format!("{}:{}", e.psk, exit_key(secret, node.id, e.id)),
            });
            if e.udp_over_tcp {
                o["udp_over_tcp"] = json!(true);
            }
            Some(o)
        })
        .collect();

    let mut inbounds = Vec::new();
    if node.anytls_on && node.anytls_port > 0 {
        // Without cert files the node keeps its own self-signed cert.
        let mut a = json!({"type": "anytls", "listen": listen(node.anytls_port)});
        if node.anytls_acme && !node.anytls_sni.is_empty() {
            a["acme"] = acme(w, node);
        } else if !node.anytls_cert.is_empty() && !node.anytls_key.is_empty() {
            a["cert"] = json!(node.anytls_cert);
            a["key"] = json!(node.anytls_key);
        }
        if !node.anytls_sni.is_empty() {
            a["server_name"] = json!(node.anytls_sni);
        }
        inbounds.push(a);
    }
    if node.vless_on && node.vless_port > 0 {
        let mut v = json!({
            "type": "vless",
            "listen": listen(node.vless_port),
            "reality": {
                "server_names": node.reality_names(),
                "private_key": node.reality_private,
                "short_ids": node.reality_short_ids(),
            }
        });
        // Empty dest follows the first server name.
        let dest = if node.reality_dest.is_empty() {
            node.reality_names().first().map(|s| format!("{s}:443")).unwrap_or_default()
        } else {
            node.reality_dest.clone()
        };
        v["reality"]["dest"] = json!(dest);
        inbounds.push(v);
    }

    let users: Vec<Value> = w
        .users
        .iter()
        .filter(|u| u.enabled && w.user_entries.get(&u.id).is_some_and(|e| e.contains(&node.id)))
        .map(|u| {
            let period = user_period(w, u, now);
            let mut v = json!({
                "name": user_counter(u.id),
                "anytls_password": u.anytls_password,
                "uuid": u.uuid,
                "flow": "xtls-rprx-vision",
                "ss_key": u.ss_key,
                "period": period,
            });
            if u.quota_bytes > 0 {
                v["quota_bytes"] = json!(u.quota_bytes);
                let base = w.used(&user_counter(u.id), &period, Some(node.id));
                if base > 0 {
                    v["used_base"] = json!(base);
                }
            }
            if u.expire_at > 0 {
                v["expire_at"] = json!(u.expire_at);
            }
            v
        })
        .collect();

    let mut config = json!({"route": route, "inbounds": inbounds, "users": users});
    if !outbounds.is_empty() {
        config["outbounds"] = Value::Array(outbounds);
    }
    config
}

fn exit(w: &World, node: &Node, secret: &str, now: i64) -> Value {
    let exits: Vec<&Exit> = w.exits.iter().filter(|e| e.node_id == node.id && !e.is_external()).collect();
    let inbounds: Vec<Value> = exits
        .iter()
        .map(|e| json!({"type": "ss2022", "listen": listen(e.port), "method": SS_METHOD, "password": e.psk}))
        .collect();
    let mut users = Vec::new();
    for entry in w.nodes.iter().filter(|n| n.is_entry()) {
        for e in &exits {
            let name = exit_counter(entry.id, e.id);
            let period = exit_period(w, e, now);
            let mut v = json!({"name": name, "ss_key": exit_key(secret, entry.id, e.id), "period": period});
            if e.quota_bytes > 0 {
                // Each exit port has one monthly quota shared by all entries:
                // every entry's counter carries what the others used.
                let others: i64 = w
                    .usage
                    .iter()
                    .filter(|((n, nm, p), _)| *n == node.id && *p == period && *nm != name && counter_exit(nm) == Some(e.id))
                    .map(|(_, v)| *v)
                    .sum();
                v["quota_bytes"] = json!(e.quota_bytes);
                if others > 0 {
                    v["used_base"] = json!(others);
                }
            }
            users.push(v);
        }
    }
    json!({"route": {"ipv4_only": node.ipv4_only}, "inbounds": inbounds, "users": users})
}

/// Leaves out inbounds of protocols the node's binary was built without, so
/// the rest of the config is still accepted. `built` is from its hello.
pub fn drop_unsupported(config: &mut Value, built: &[String]) {
    if built.is_empty() {
        return;
    }
    if let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) {
        inbounds.retain(|i| i["type"].as_str().is_some_and(|t| built.iter().any(|b| b == t)));
    }
}

/// The config with every used_base removed: a change here is pushed at once,
/// while used_base alone only changes every minute or so.
pub fn shape(config: &Value) -> Value {
    let mut c = config.clone();
    if let Some(users) = c.get_mut("users").and_then(Value::as_array_mut) {
        for u in users {
            if let Some(o) = u.as_object_mut() {
                o.remove("used_base");
            }
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters() {
        assert_eq!(counter_exit(&exit_counter(3, 12)), Some(12));
        assert_eq!(counter_exit("u4"), None);
        assert_eq!(counter_exit("nax2"), None);
    }
}
