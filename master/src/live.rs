//! In-memory state of connected nodes: the control channel, the last report
//! and short histories for the probe page. Nothing here survives a restart.

use axum::extract::ws::Message;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::Notify;

/// Speed history on the probe page: one point every 5 s.
pub const SPEED_POINTS: usize = 36;
/// Latency history per ISP: one point per probe round (30 s) for an hour.
pub const PROBE_POINTS: usize = 120;
/// Probe targets kept per node (the panel configures three).
const MAX_PROBES: usize = 8;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Hello {
    pub node_version: String,
    pub protocols: Vec<String>,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub config_rev: i64,
    pub features: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct System {
    pub cpu_pct: f64,
    pub load1: f64,
    pub mem_total: i64,
    pub mem_used: i64,
    pub swap_total: i64,
    pub swap_used: i64,
    pub disk_total: i64,
    pub disk_used: i64,
    pub net_rx: i64,
    pub net_tx: i64,
    pub rx_rate: f64,
    pub tx_rate: f64,
    pub tcp_conns: i64,
    pub udp_conns: i64,
    pub uptime_s: i64,
    pub rss: i64,
    pub tcp_retrans_pct: f64,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct UserReport {
    pub name: String,
    pub period: String,
    pub up: i64,
    pub down: i64,
    pub conns: i64,
    pub blocked: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProbeReport {
    pub name: String,
    pub host: String,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    pub samples: i64,
    /// End of the probe round; every target in a round shares it.
    pub at: i64,
}

/// Health of one outbound as the node's own check sees it.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct OutboundHealth {
    pub tag: String,
    pub alive: bool,
    pub latency_ms: f64,
    pub checked_at: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Report {
    pub ts: i64,
    pub config_rev: i64,
    pub users: Vec<UserReport>,
    /// False when `users` only lists the users whose figures changed since
    /// the node's previous report (nodes that saw `report_delta`); older
    /// nodes always send everyone and leave the field out.
    #[serde(default = "full_by_default")]
    pub full: bool,
    pub system: Option<System>,
    /// Present only in the first report after a probe round finished.
    pub probes: Vec<ProbeReport>,
    pub outbounds: Vec<OutboundHealth>,
    pub certs: Vec<CertStatus>,
    /// The REALITY dest candidates' latest round, in the first report after
    /// it (and again after a reconnect).
    pub dest_probes: Vec<ProbeReport>,
}

/// A REALITY dest candidate (host:port) as the node last timed it; shown to
/// the admin only.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DestLatency {
    pub host: String,
    pub latency_ms: f64,
    pub loss_pct: f64,
    pub at: i64,
}

/// At most this many dest candidates are kept per node; the master sends
/// fewer.
const MAX_DESTS: usize = 16;

fn full_by_default() -> bool {
    true
}

/// A certificate the node serves, as of its last report.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct CertStatus {
    pub domain: String,
    /// "acme" or "self-signed".
    pub issuer: String,
    pub not_after: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub next_try: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct ProbePoint {
    pub ts: i64,
    pub latency: f64,
    pub jitter: f64,
    pub loss: f64,
}

pub struct Conn {
    pub id: u64,
    pub tx: Sender<Message>,
    /// Ends the connection's serve task (token rotated, node deleted, or
    /// replaced by a newer connection).
    pub stop: Arc<Notify>,
}

impl Conn {
    /// Queues a message. A node too slow to take it is cut off rather than
    /// let the queue grow: it gets the latest config when it reconnects.
    pub fn send(&self, msg: Message) -> bool {
        if self.tx.try_send(msg).is_ok() {
            true
        } else {
            self.stop.notify_one();
            false
        }
    }
}

#[derive(Default)]
pub struct NodeLive {
    pub conn: Option<Conn>,
    pub connected_at: i64,
    pub last_seen: i64,
    pub hello: Hello,
    pub system: Option<System>,
    /// Last cumulative interface counters, for monthly traffic.
    pub net: Option<(i64, i64)>,
    pub probes: HashMap<String, VecDeque<ProbePoint>>,
    pub last_probe_ts: i64,
    /// User counters online right now, by counter name.
    pub conns: HashMap<String, i64>,
    /// Exit health from the last report, by outbound tag.
    pub outbounds: HashMap<String, OutboundHealth>,
    pub certs: Vec<CertStatus>,
    pub applied_rev: i64,
    pub apply_error: String,
    pub sent_rev: i64,
    pub sent_hash: String,
    pub sent_shape: String,
    pub sent_at: i64,
    /// The REALITY dest candidates' latest round.
    pub dest_latency: Vec<DestLatency>,
    /// Each user's (used_base, used_self) as this connection last sent them,
    /// for a node that takes usage messages.
    pub sent_usage: HashMap<String, (i64, i64)>,
}

impl NodeLive {
    pub fn online(&self) -> bool {
        self.conn.is_some()
    }

    /// Keeps the dest round a report brought: a few host:port names with
    /// figures in range, whatever the node sends.
    pub fn record_dest_probes(&mut self, report: &Report, now: i64) {
        let at = |t: i64| if t > 0 && t <= now + 60 { t } else { now };
        self.dest_latency = report
            .dest_probes
            .iter()
            .filter(|p| p.host.len() <= 261 && p.host.contains(':') && p.latency_ms.is_finite() && p.loss_pct.is_finite())
            .take(MAX_DESTS)
            .map(|p| DestLatency {
                host: p.host.clone(),
                latency_ms: p.latency_ms.clamp(0.0, 60_000.0),
                loss_pct: p.loss_pct.clamp(0.0, 100.0),
                at: at(p.at),
            })
            .collect();
    }

    pub fn record_probes(&mut self, report: &Report, now: i64) {
        let Some(first) = report.probes.first() else { return };
        let ts = if first.at > 0 { first.at } else { now };
        if ts <= self.last_probe_ts {
            return;
        }
        self.last_probe_ts = ts;
        for p in &report.probes {
            // Names come from the node: keep a handful of short ones only.
            if p.name.len() > 16 || (!self.probes.contains_key(&p.name) && self.probes.len() >= MAX_PROBES) {
                continue;
            }
            let h = self.probes.entry(p.name.clone()).or_default();
            let latency = if p.samples > 0 { p.latency_ms } else { 0.0 };
            h.push_back(ProbePoint { ts, latency, jitter: p.jitter_ms, loss: p.loss_pct });
            while h.len() > PROBE_POINTS {
                h.pop_front();
            }
        }
    }
}

#[derive(Default)]
pub struct Live {
    pub nodes: HashMap<i64, NodeLive>,
    /// Total (rx, tx) bytes/s across online nodes, oldest first.
    pub speed: VecDeque<(f64, f64)>,
    pub next_conn: u64,
}

impl Live {
    pub fn sample_speed(&mut self) {
        let (mut rx, mut tx) = (0.0, 0.0);
        for n in self.nodes.values().filter(|n| n.online()) {
            if let Some(s) = &n.system {
                rx += s.rx_rate;
                tx += s.tx_rate;
            }
        }
        self.speed.push_back((rx, tx));
        while self.speed.len() > SPEED_POINTS {
            self.speed.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dest_probes_are_bounded() {
        let probe = |host: &str, latency: f64, at: i64| ProbeReport { host: host.into(), latency_ms: latency, loss_pct: 250.0, at, ..Default::default() };
        let mut report = Report::default();
        report.dest_probes = vec![probe("www.apple.com:443", 38.5, 90), probe("no-port", 1.0, 90), probe("big.example:443", f64::NAN, 90), probe("far.example:443", 1e12, 10_000)];
        report.dest_probes.extend((0..40).map(|i| probe(&format!("h{i}.example:443"), 1.0, 90)));
        let mut l = NodeLive::default();
        l.record_dest_probes(&report, 100);
        assert_eq!(l.dest_latency.len(), MAX_DESTS);
        assert_eq!((l.dest_latency[0].host.as_str(), l.dest_latency[0].latency_ms, l.dest_latency[0].loss_pct, l.dest_latency[0].at), ("www.apple.com:443", 38.5, 100.0, 90));
        assert_eq!((l.dest_latency[1].host.as_str(), l.dest_latency[1].latency_ms, l.dest_latency[1].at), ("far.example:443", 60_000.0, 100));
    }

    #[test]
    fn reports_are_full_unless_marked() {
        let old: Report = serde_json::from_str(r#"{"type":"report","users":[{"name":"u1","up":1}]}"#).unwrap();
        assert!(old.full, "a report from an older node lists every user");
        let delta: Report = serde_json::from_str(r#"{"type":"report","full":false,"users":[]}"#).unwrap();
        assert!(!delta.full);
    }
}
