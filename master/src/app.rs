//! Shared state and the logic that keeps every connected node's config in
//! step with the database.

use axum::extract::ws::Message;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::db;
use crate::live::{Hello, Live, Report};
use crate::nodecfg::{self, ProbeTarget};
use crate::period::{month_label, now};
use crate::util::{hex, sha256};

/// Upper bound on a reported per-user counter (1 PiB).
const MAX_COUNTER: i64 = 1 << 50;
/// Upper bound on one report interval's interface traffic (1 TiB).
const MAX_INTERVAL_BYTES: i64 = 1 << 40;

/// A used_base-only change is pushed at most this often.
const USAGE_PUSH_INTERVAL: i64 = 60;

/// Sync requests: at most one run at a time; requests during a run are
/// collected here for the next one.
static SYNC: Mutex<SyncRequests> = Mutex::new(SyncRequests { running: false, all: false, nodes: BTreeSet::new() });

struct SyncRequests {
    running: bool,
    all: bool,
    nodes: BTreeSet<i64>,
}

pub struct TlsInfo {
    /// Hex SHA-256 of the leaf certificate (DER), shown for browsers.
    pub cert_sha256: String,
    /// Hex SHA-256 of the public key, which nodes pin: it survives moving
    /// the panel to a CA certificate for the same key.
    pub spki_sha256: String,
    /// curl --pinnedpubkey value for the install command, when self-signed.
    pub spki_pin: Option<String>,
}

pub struct App {
    pub db: Mutex<Connection>,
    pub live: Mutex<Live>,
    pub secret: String,
    pub tls: Option<TlsInfo>,
    pub dist: PathBuf,
    /// Behind a reverse proxy: take the client address from X-Forwarded-For.
    pub trust_proxy: bool,
    /// Set when the master serves its own generated key (see panel_cert).
    pub panel_tls: Option<crate::panel_cert::PanelTls>,
}

impl App {
    pub fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn live(&self) -> MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn probe_targets(conn: &Connection) -> Vec<ProbeTarget> {
        db::get_setting(conn, "probe_targets")
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_str(&v).ok())
            .unwrap_or_else(nodecfg::default_probe_targets)
    }

    /// Rebuilds every connected node's config and pushes the ones that
    /// changed. Called after each edit and every 30 s (periods roll over,
    /// used_base moves as other nodes report traffic).
    ///
    /// The work runs on a blocking thread, and the database and live locks
    /// are only held to read the world and to record what was sent, not
    /// while configs are built. Requests that arrive during a run fold into
    /// one more run, so a burst of edits or reconnects costs at most two
    /// runs instead of one per request; none is dropped.
    pub fn sync(self: &Arc<Self>) {
        self.request_sync(None);
    }

    /// Like `sync`, for one node that just connected: the others' configs
    /// did not change because of it.
    pub fn sync_node(self: &Arc<Self>, node_id: i64) {
        self.request_sync(Some(node_id));
    }

    fn request_sync(self: &Arc<Self>, node: Option<i64>) {
        {
            let mut s = SYNC.lock().unwrap_or_else(|e| e.into_inner());
            match node {
                Some(id) => {
                    s.nodes.insert(id);
                }
                None => s.all = true,
            }
            if s.running {
                return;
            }
            s.running = true;
        }
        let app = self.clone();
        let run = move || loop {
            let scope = {
                let mut s = SYNC.lock().unwrap_or_else(|e| e.into_inner());
                if !s.all && s.nodes.is_empty() {
                    s.running = false;
                    return;
                }
                let scope = if s.all { None } else { Some(std::mem::take(&mut s.nodes)) };
                s.all = false;
                s.nodes.clear();
                scope
            };
            app.sync_now(scope.as_ref());
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn_blocking(run);
            }
            Err(_) => run(),
        }
    }

    fn sync_now(&self, only: Option<&BTreeSet<i64>>) {
        let ts = now();
        let (world, probes) = {
            let conn = self.db();
            if let Err(e) = db::ensure_self_certs(&conn) {
                eprintln!("sync: anytls certificates: {e}");
            }
            let world = match db::load_world(&conn) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("sync: load: {e}");
                    return;
                }
            };
            (world, Self::probe_targets(&conn))
        };
        // The connected nodes and what they were last sent.
        let targets: Vec<(i64, u64, Vec<String>, String, String, i64, i64)> = {
            let live = self.live();
            world
                .nodes
                .iter()
                .filter(|n| only.is_none_or(|ids| ids.contains(&n.id)))
                .filter_map(|n| {
                    let l = live.nodes.get(&n.id)?;
                    let c = l.conn.as_ref()?;
                    Some((n.id, c.id, l.hello.protocols.clone(), l.sent_hash.clone(), l.sent_shape.clone(), l.sent_at, l.sent_rev))
                })
                .collect()
        };
        let mut pushes = Vec::new();
        for (node_id, conn_id, protocols, sent_hash, sent_shape, sent_at, sent_rev) in targets {
            let Some(node) = world.node(node_id) else { continue };
            let mut config = nodecfg::build(&world, node, &self.secret, &probes, ts);
            nodecfg::drop_unsupported(&mut config, &protocols);
            if let Some(t) = &self.tls {
                config["master_spki"] = json!(t.spki_sha256);
            }
            let full = serde_json::to_string(&config).unwrap_or_default();
            let hash = hex(&sha256(full.as_bytes()));
            if hash == sent_hash {
                continue;
            }
            let shape = hex(&sha256(serde_json::to_string(&nodecfg::shape(&config)).unwrap_or_default().as_bytes()));
            if shape == sent_shape && ts - sent_at < USAGE_PUSH_INTERVAL {
                continue;
            }
            let rev = node.config_rev.max(sent_rev) + 1;
            let msg = format!(r#"{{"type":"config","rev":{rev},"config":{full}}}"#);
            pushes.push((node_id, conn_id, rev, hash, shape, msg));
        }
        if pushes.is_empty() {
            return;
        }
        let mut sent = Vec::new();
        {
            let mut live = self.live();
            for (node_id, conn_id, rev, hash, shape, msg) in pushes {
                let Some(l) = live.nodes.get_mut(&node_id) else { continue };
                // A node that reconnected meanwhile gets its own run.
                let Some(c) = l.conn.as_ref().filter(|c| c.id == conn_id) else { continue };
                if !c.send(Message::Text(msg.into())) {
                    continue;
                }
                l.sent_rev = rev;
                l.sent_hash = hash.clone();
                l.sent_shape = shape.clone();
                l.sent_at = ts;
                sent.push((node_id, rev, hash, shape));
            }
        }
        let conn = self.db();
        let saved = conn.unchecked_transaction().and_then(|tx| {
            for (node_id, rev, hash, shape) in &sent {
                tx.execute(
                    "UPDATE nodes SET config_rev=?1, config_hash=?2, config_shape=?3 WHERE id=?4",
                    params![rev, hash, shape, node_id],
                )?;
            }
            tx.commit()
        });
        if let Err(e) = saved {
            eprintln!("sync: save rev: {e}");
        }
    }

    /// A node finished its hello: if it still runs the config we last sent,
    /// there is nothing to push.
    /// Records a node's hello; returns whether its address changed.
    pub fn on_hello(&self, node_id: i64, hello: Hello, ip: &str) -> bool {
        let conn = self.db();
        let moved = conn.execute("UPDATE nodes SET last_ip=?1 WHERE id=?2 AND last_ip<>?1", params![ip, node_id]).unwrap_or(0) > 0;
        let stored: Option<(i64, String, String)> = conn
            .query_row("SELECT config_rev, config_hash, config_shape FROM nodes WHERE id=?1", [node_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .ok();
        let mut live = self.live();
        let l = live.nodes.entry(node_id).or_default();
        if let Some((rev, hash, shape)) = stored {
            if rev > 0 && hello.config_rev == rev {
                l.sent_rev = rev;
                l.sent_hash = hash;
                l.sent_shape = shape;
                l.applied_rev = rev;
            } else {
                l.sent_rev = rev;
                l.sent_hash.clear();
                l.sent_shape.clear();
            }
        }
        l.hello = hello;
        moved
    }

    pub fn on_report(&self, node_id: i64, report: Report) {
        let ts = now();
        let conn = self.db();
        // A node may only report the counters the master gave it, with sane
        // values: anything else could block or free other nodes' users.
        let allowed = db::node_counters(&conn, node_id).unwrap_or_default();
        let rows: Vec<(String, String, i64, i64)> = report
            .users
            .iter()
            .filter(|u| allowed.contains(&u.name) && !u.period.is_empty() && u.period.len() <= 32)
            .map(|u| (u.name.clone(), u.period.clone(), u.up.clamp(0, MAX_COUNTER), u.down.clamp(0, MAX_COUNTER)))
            .collect();
        if let Err(e) = db::store_usage(&conn, node_id, &rows, ts) {
            eprintln!("report: store usage: {e}");
        }
        let tz = db::get_setting(&conn, "tz_offset").ok().flatten().and_then(|v| v.parse().ok()).unwrap_or(480);
        let mut live = self.live();
        let l = live.nodes.entry(node_id).or_default();
        l.last_seen = ts;
        l.conns = report.users.iter().map(|u| (u.name.clone(), u.conns)).collect();
        l.outbounds = report.outbounds.iter().map(|o| (o.tag.clone(), o.clone())).collect();
        // Bounded: the panel turns these into dates, and the node picks them.
        let latest = ts + 20 * 365 * 86_400;
        l.certs = report
            .certs
            .iter()
            .take(8)
            .cloned()
            .map(|mut c| {
                c.not_after = c.not_after.clamp(0, latest);
                c.next_try = c.next_try.clamp(0, latest);
                c.domain = c.domain.chars().take(253).collect();
                c.error = c.error.chars().take(300).collect();
                c
            })
            .collect();
        l.record_probes(&report, ts);
        if report.config_rev > 0 {
            l.applied_rev = report.config_rev;
        }
        if let Some(s) = report.system {
            let (rx, tx) = (s.net_rx, s.net_tx);
            if let Some((prx, ptx)) = l.net {
                // Counters restart from zero when the machine reboots.
                let drx = (if rx >= prx { rx - prx } else { rx }).clamp(0, MAX_INTERVAL_BYTES);
                let dtx = (if tx >= ptx { tx - ptx } else { tx }).clamp(0, MAX_INTERVAL_BYTES);
                if drx > 0 || dtx > 0 {
                    if let Err(e) = db::add_node_month(&conn, node_id, &month_label(ts, tz), drx, dtx) {
                        eprintln!("report: month traffic: {e}");
                    }
                }
            }
            l.net = Some((rx, tx));
            l.system = Some(s);
        }
    }

    pub fn on_applied(&self, node_id: i64, msg: &Value) {
        let mut live = self.live();
        let l = live.nodes.entry(node_id).or_default();
        l.applied_rev = msg["rev"].as_i64().unwrap_or(0);
        l.apply_error = msg["error"].as_str().unwrap_or("").chars().take(500).collect();
        // Noted after the live lock is released: sync takes the database
        // lock first, then live.
        let accepts_key = l.apply_error.is_empty() && self.panel_tls.is_some() && l.hello.features.iter().any(|f| f == "spki_pin");
        if !l.apply_error.is_empty() {
            eprintln!("node {node_id}: config rev {} rejected: {:?}", l.applied_rev, l.apply_error);
        }
        drop(live);
        if accepts_key {
            let _ = self.db().execute("UPDATE nodes SET spki_ready=1 WHERE id=?1 AND spki_ready=0", [node_id]);
        }
    }

    /// Drops a node's control connection, e.g. after its token changed.
    pub fn kick(&self, node_id: i64) {
        let mut live = self.live();
        if let Some(l) = live.nodes.get_mut(&node_id) {
            if let Some(c) = l.conn.take() {
                c.stop.notify_one();
            }
        }
    }
}
