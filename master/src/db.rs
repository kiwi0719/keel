//! SQLite store. Everything the panel edits lives here; live probe data does
//! not (see live.rs). The data set is small (a handful of nodes, tens of
//! users), so callers load the whole world and work on it in memory.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

use crate::util::{random_b64, random_hex, random_uuid};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes(
  id INTEGER PRIMARY KEY,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('entry','exit')),
  host TEXT NOT NULL DEFAULT '',
  last_ip TEXT NOT NULL DEFAULT '',
  token TEXT NOT NULL UNIQUE,
  sort INTEGER NOT NULL DEFAULT 0,
  ipv4_only INTEGER NOT NULL DEFAULT 1,
  direct_list TEXT NOT NULL DEFAULT '',
  anytls_on INTEGER NOT NULL DEFAULT 0,
  anytls_port INTEGER NOT NULL DEFAULT 0,
  anytls_sni TEXT NOT NULL DEFAULT '',
  vless_on INTEGER NOT NULL DEFAULT 0,
  vless_port INTEGER NOT NULL DEFAULT 0,
  reality_dest TEXT NOT NULL DEFAULT '',
  reality_sni TEXT NOT NULL DEFAULT '',
  reality_private TEXT NOT NULL DEFAULT '',
  reality_public TEXT NOT NULL DEFAULT '',
  reality_short_id TEXT NOT NULL DEFAULT '',
  ss_on INTEGER NOT NULL DEFAULT 0,
  ss_port INTEGER NOT NULL DEFAULT 0,
  ss_psk TEXT NOT NULL DEFAULT '',
  default_exit INTEGER NOT NULL DEFAULT 0,
  config_rev INTEGER NOT NULL DEFAULT 0,
  config_hash TEXT NOT NULL DEFAULT '',
  config_shape TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS exits(
  id INTEGER PRIMARY KEY,
  -- NULL for an external exit: a third-party server entries dial directly.
  node_id INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  port INTEGER NOT NULL DEFAULT 0,
  psk TEXT NOT NULL DEFAULT '',
  quota_bytes INTEGER NOT NULL DEFAULT 0,
  reset_day INTEGER NOT NULL DEFAULT 1,
  udp_over_tcp INTEGER NOT NULL DEFAULT 0,
  sort INTEGER NOT NULL DEFAULT 0,
  -- ss: an SS 2022 port on a keel exit node. External, imported from a share
  -- link: vless (plain TCP, uuid) or shadowsocks (method, password in psk).
  kind TEXT NOT NULL DEFAULT 'ss',
  server TEXT NOT NULL DEFAULT '',
  uuid TEXT NOT NULL DEFAULT '',
  method TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS rulesets(
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  domains TEXT NOT NULL DEFAULT '',
  sort INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS entry_rules(
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  ruleset TEXT NOT NULL REFERENCES rulesets(id) ON DELETE CASCADE,
  exit_id INTEGER NOT NULL,
  sort INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(node_id, ruleset)
);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT NOT NULL DEFAULT '',
  quota_bytes INTEGER NOT NULL DEFAULT 0,
  expire_at INTEGER NOT NULL DEFAULT 0,
  reset_day INTEGER NOT NULL DEFAULT 1,
  reset_period TEXT NOT NULL DEFAULT '',
  reset_seq INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1,
  anytls_password TEXT NOT NULL,
  uuid TEXT NOT NULL,
  ss_key TEXT NOT NULL,
  sub_token TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_entries(
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  PRIMARY KEY(user_id, node_id)
);
-- Absolute per-period counters as nodes report them. Kept when a node is
-- deleted so a user's total for the period does not drop.
CREATE TABLE IF NOT EXISTS usage(
  node_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  period TEXT NOT NULL,
  up INTEGER NOT NULL,
  down INTEGER NOT NULL,
  updated INTEGER NOT NULL,
  PRIMARY KEY(node_id, name, period)
);
-- load_world reads the last 70 days of a table kept for 400.
CREATE INDEX IF NOT EXISTS usage_updated ON usage(updated);
-- node_counters looks entries up by node.
CREATE INDEX IF NOT EXISTS user_entries_node ON user_entries(node_id);
-- A subscription reads one user's rows. Only inserts touch it: reports
-- change up, down and updated, never the name.
CREATE INDEX IF NOT EXISTS usage_name ON usage(name);
CREATE TABLE IF NOT EXISTS node_month(
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  month TEXT NOT NULL,
  rx INTEGER NOT NULL DEFAULT 0,
  tx INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(node_id, month)
);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, expires INTEGER NOT NULL);
"#;

/// Columns added after the first release: (table, column, type).
const MIGRATIONS: &[(&str, &str, &str)] = &[
    // Fallback exits in order, comma-separated exit ids (0 = direct).
    ("nodes", "default_fallback", "TEXT NOT NULL DEFAULT ''"),
    ("entry_rules", "fallback", "TEXT NOT NULL DEFAULT ''"),
    // AnyTLS certificate files on the node; empty = the node's own self-signed cert.
    ("nodes", "anytls_cert", "TEXT NOT NULL DEFAULT ''"),
    ("nodes", "anytls_key", "TEXT NOT NULL DEFAULT ''"),
    // Self-signed AnyTLS certificate the master makes for an entry without
    // cert files or ACME, so subscriptions can pin it. self_name records the
    // name and year it was made for.
    ("nodes", "anytls_self_cert", "TEXT NOT NULL DEFAULT ''"),
    ("nodes", "anytls_self_key", "TEXT NOT NULL DEFAULT ''"),
    ("nodes", "anytls_self_name", "TEXT NOT NULL DEFAULT ''"),
    // Mixed into the keys this entry uses on exits; a new one (on token
    // rotation) makes keys a leaked node config held useless.
    ("nodes", "key_salt", "TEXT NOT NULL DEFAULT ''"),
    // 1 once the node applied a config with master_spki: it accepts the
    // master's key, so the panel may move to a CA certificate.
    ("nodes", "spki_ready", "INTEGER NOT NULL DEFAULT 0"),
    // 1: the user's AnyTLS password and UUID differ per entry (derived from
    // the stored ones), so one entry's config does not open the others.
    // Users from before keep one set until their subscription is reset.
    ("users", "per_entry", "INTEGER NOT NULL DEFAULT 0"),
    // External VLESS exit over TLS: the certificate name to verify ('' = plain TCP).
    ("exits", "tls_sni", "TEXT NOT NULL DEFAULT ''"),
    // External VLESS exit: flow and REALITY settings as JSON ('' = none).
    ("exits", "vless_opts", "TEXT NOT NULL DEFAULT ''"),
    // uTLS fingerprint clients present for Reality (subscription only).
    ("nodes", "reality_fp", "TEXT NOT NULL DEFAULT 'chrome'"),
    // Public ports for NAT boxes, where the provider maps public -> listen
    // port. 0 = clients use the listen port.
    ("nodes", "anytls_pub", "INTEGER NOT NULL DEFAULT 0"),
    ("nodes", "vless_pub", "INTEGER NOT NULL DEFAULT 0"),
    ("exits", "pub_port", "INTEGER NOT NULL DEFAULT 0"),
    // AnyTLS gets a Let's Encrypt cert for anytls_sni from the node itself.
    ("nodes", "anytls_acme", "INTEGER NOT NULL DEFAULT 0"),
];

/// Databases from before external exits have exits.node_id NOT NULL and no
/// kind/server/uuid columns; SQLite cannot drop NOT NULL, so rebuild the table.
fn migrate_exits(conn: &mut Connection) -> rusqlite::Result<()> {
    let old: bool = conn.prepare("SELECT 1 FROM pragma_table_info('exits') WHERE name='node_id' AND \"notnull\"=1")?.exists([])?;
    if !old {
        return Ok(());
    }
    conn.pragma_update(None, "foreign_keys", "OFF")?;
    let tx = conn.transaction()?;
    let create = SCHEMA
        .split("CREATE TABLE IF NOT EXISTS exits(")
        .nth(1)
        .and_then(|rest| rest.split(");").next())
        .expect("exits table in SCHEMA");
    tx.execute_batch(&format!(
        "CREATE TABLE exits_new({create});
         INSERT INTO exits_new(id,node_id,name,port,psk,quota_bytes,reset_day,udp_over_tcp,sort)
           SELECT id,node_id,name,port,psk,quota_bytes,reset_day,udp_over_tcp,sort FROM exits;
         DROP TABLE exits;
         ALTER TABLE exits_new RENAME TO exits;"
    ))?;
    tx.commit()?;
    conn.pragma_update(None, "foreign_keys", "ON")
}

/// Comma- or space-separated text as a list, empty items dropped.
pub fn split_list(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c.is_whitespace()).filter(|x| !x.is_empty()).map(str::to_string).collect()
}

pub fn ids_from_text(s: &str) -> Vec<i64> {
    s.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

pub fn ids_to_text(ids: &[i64]) -> String {
    ids.iter().map(i64::to_string).collect::<Vec<_>>().join(",")
}

/// Rule sets offered for split routing; lists live in rules/ at the repo root.
/// Nodes match rules top to bottom, so narrower lists come first (Gemini is in
/// both ai and google, YouTube in both youtube and streaming).
const RULESETS: &[(&str, &str, &str, &str)] = &[
    ("ai", "AI", "OpenAI · Claude · Gemini", include_str!("../../rules/ai.list")),
    ("youtube", "YouTube", "", include_str!("../../rules/youtube.list")),
    ("streaming", "流媒体", "Netflix · Disney+ · HBO", include_str!("../../rules/streaming.list")),
    ("telegram", "Telegram", "", include_str!("../../rules/telegram.list")),
    ("games", "游戏", "Steam · Epic · PSN", include_str!("../../rules/games.list")),
    ("google", "Google", "", include_str!("../../rules/google.list")),
];

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    let mut conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(SCHEMA)?;
    migrate_exits(&mut conn)?;
    for (table, col, ddl) in MIGRATIONS {
        let has: bool = conn
            .prepare(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name=?1"))?
            .exists([col])?;
        if !has {
            conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {col} {ddl}"))?;
        }
    }
    for (i, (id, label, desc, list)) in RULESETS.iter().enumerate() {
        // Built-in lists follow the binary; labels the user never edits.
        conn.execute(
            "INSERT INTO rulesets(id,label,description,domains,sort) VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(id) DO UPDATE SET domains=excluded.domains, sort=excluded.sort",
            params![id, label, desc, list, i as i64],
        )?;
    }
    Ok(conn)
}

/// A second connection to the database, for reads that should not wait
/// behind writes: with WAL they run side by side. It refuses writes. Opened
/// after `open`, so the files exist with their modes.
pub fn open_reader(path: &Path) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.pragma_update(None, "query_only", "ON")?;
    Ok(conn)
}

/// A new id for `table` ("nodes" or "exits") that was never used before,
/// even by a deleted row: ids name config tags and usage counters, so a
/// reused id would inherit a deleted node's history.
pub fn fresh_id(conn: &Connection, table: &str) -> rusqlite::Result<i64> {
    let key = format!("last_{table}_id");
    let floor: i64 = get_setting(conn, &key)?.and_then(|v| v.parse().ok()).unwrap_or(0);
    let max: i64 = conn.query_row(&format!("SELECT COALESCE(MAX(id),0) FROM {table}"), [], |r| r.get(0))?;
    let id = floor.max(max) + 1;
    set_setting(conn, &key, &id.to_string())?;
    Ok(id)
}

pub fn get_setting(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM settings WHERE key=?1", [key], |r| r.get(0)).optional()
}

pub fn set_setting(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Node {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub role: String,
    pub host: String,
    pub last_ip: String,
    #[serde(skip)]
    pub token: String,
    pub sort: i64,
    pub ipv4_only: bool,
    pub direct_list: String,
    pub anytls_on: bool,
    pub anytls_port: i64,
    pub anytls_sni: String,
    pub anytls_cert: String,
    pub anytls_key: String,
    pub anytls_pub: i64,
    pub anytls_acme: bool,
    #[serde(skip)]
    pub anytls_self_cert: String,
    #[serde(skip)]
    pub anytls_self_key: String,
    #[serde(skip)]
    pub key_salt: String,
    pub vless_on: bool,
    pub vless_port: i64,
    pub reality_dest: String,
    pub reality_sni: String,
    #[serde(skip)]
    pub reality_private: String,
    pub reality_public: String,
    pub reality_short_id: String,
    pub reality_fp: String,
    pub vless_pub: i64,
    // SS entry inbounds are retired (entries speak AnyTLS / Reality only);
    // the columns stay so old databases load.
    pub ss_on: bool,
    pub ss_port: i64,
    #[serde(skip)]
    #[allow(dead_code)]
    pub ss_psk: String,
    pub default_exit: i64,
    pub default_fallback: Vec<i64>,
    #[serde(skip)]
    pub config_rev: i64,
}

impl Node {
    pub fn is_entry(&self) -> bool {
        self.role == "entry"
    }
    /// Reality server names; the first is the one clients send.
    pub fn reality_names(&self) -> Vec<String> {
        split_list(&self.reality_sni)
    }
    /// Reality short ids; the first goes into subscriptions.
    pub fn reality_short_ids(&self) -> Vec<String> {
        split_list(&self.reality_short_id)
    }
    /// Address clients and entries use to reach this node.
    pub fn address(&self) -> &str {
        if self.host.is_empty() {
            &self.last_ip
        } else {
            &self.host
        }
    }
}

const NODE_COLS: &str = "id,code,name,role,host,last_ip,token,sort,ipv4_only,direct_list,anytls_on,anytls_port,anytls_sni,vless_on,vless_port,reality_dest,reality_sni,reality_private,reality_public,reality_short_id,ss_on,ss_port,ss_psk,default_exit,config_rev,default_fallback,anytls_cert,anytls_key,reality_fp,anytls_pub,vless_pub,anytls_acme,anytls_self_cert,anytls_self_key,key_salt";

fn node_from_row(r: &rusqlite::Row) -> rusqlite::Result<Node> {
    Ok(Node {
        id: r.get(0)?,
        code: r.get(1)?,
        name: r.get(2)?,
        role: r.get(3)?,
        host: r.get(4)?,
        last_ip: r.get(5)?,
        token: r.get(6)?,
        sort: r.get(7)?,
        ipv4_only: r.get(8)?,
        direct_list: r.get(9)?,
        anytls_on: r.get(10)?,
        anytls_port: r.get(11)?,
        anytls_sni: r.get(12)?,
        vless_on: r.get(13)?,
        vless_port: r.get(14)?,
        reality_dest: r.get(15)?,
        reality_sni: r.get(16)?,
        reality_private: r.get(17)?,
        reality_public: r.get(18)?,
        reality_short_id: r.get(19)?,
        ss_on: r.get(20)?,
        ss_port: r.get(21)?,
        ss_psk: r.get(22)?,
        default_exit: r.get(23)?,
        config_rev: r.get(24)?,
        default_fallback: ids_from_text(&r.get::<_, String>(25)?),
        anytls_cert: r.get(26)?,
        anytls_key: r.get(27)?,
        reality_fp: r.get(28)?,
        anytls_pub: r.get(29)?,
        vless_pub: r.get(30)?,
        anytls_acme: r.get(31)?,
        anytls_self_cert: r.get(32)?,
        anytls_self_key: r.get(33)?,
        key_salt: r.get(34)?,
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct Exit {
    pub id: i64,
    pub node_id: i64,
    pub name: String,
    pub port: i64,
    /// Port entries dial when a NAT provider maps it to `port`; 0 = `port`.
    pub pub_port: i64,
    #[serde(skip)]
    pub psk: String,
    pub quota_bytes: i64,
    pub reset_day: i64,
    pub udp_over_tcp: bool,
    pub sort: i64,
    /// "ss" (a port on a keel exit node, node_id set), or an external exit
    /// with node_id 0: "vless" or "shadowsocks" (password in psk).
    pub kind: String,
    /// External: host:port of the third-party server.
    pub server: String,
    #[serde(skip)]
    pub uuid: String,
    /// External shadowsocks: the cipher.
    pub method: String,
    /// External VLESS over TLS: the certificate name; empty for plain TCP.
    pub tls_sni: String,
    /// External VLESS: flow and REALITY settings (JSON), empty for none.
    #[serde(skip)]
    pub vless_opts: String,
}

impl Exit {
    /// How traffic to an external VLESS exit is protected, for the panel:
    /// "reality", "tls" or "plain"; empty for other exits.
    pub fn transport(&self) -> &'static str {
        if self.kind != "vless" {
            ""
        } else if self.vless_opts.contains("\"reality\"") {
            "reality"
        } else if !self.tls_sni.is_empty() {
            "tls"
        } else {
            "plain"
        }
    }
}

impl Exit {
    pub fn public_port(&self) -> i64 {
        if self.pub_port > 0 {
            self.pub_port
        } else {
            self.port
        }
    }
    pub fn is_external(&self) -> bool {
        self.kind != "ss"
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleSet {
    pub id: String,
    pub label: String,
    pub description: String,
    #[serde(skip)]
    pub domains: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EntryRule {
    pub node_id: i64,
    pub ruleset: String,
    pub exit_id: i64,
    pub fallback: Vec<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub plan: String,
    pub quota_bytes: i64,
    pub expire_at: i64,
    pub reset_day: i64,
    #[serde(skip)]
    pub reset_period: String,
    #[serde(skip)]
    pub reset_seq: i64,
    pub enabled: bool,
    #[serde(skip)]
    pub anytls_password: String,
    #[serde(skip)]
    pub uuid: String,
    #[serde(skip)]
    pub ss_key: String,
    #[serde(skip)]
    pub sub_token: String,
    #[serde(skip)]
    pub per_entry: bool,
}

impl User {
    /// The AnyTLS password and VLESS UUID this user has on one entry.
    pub fn credentials_for(&self, entry: i64) -> (String, String) {
        if !self.per_entry {
            return (self.anytls_password.clone(), self.uuid.clone());
        }
        let pw = crate::util::hex(&crate::util::sha256(format!("keel entry anytls\0{}\0{entry}", self.anytls_password).as_bytes()));
        let mut u = crate::util::sha256(format!("keel entry uuid\0{}\0{entry}", self.uuid).as_bytes());
        u[6] = (u[6] & 0x0f) | 0x40; // version 4 layout
        u[8] = (u[8] & 0x3f) | 0x80;
        let h = crate::util::hex(&u[..16]);
        (pw[..32].to_string(), format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32]))
    }
}

const USER_COLS: &str = "id,name,plan,quota_bytes,expire_at,reset_day,reset_period,reset_seq,enabled,anytls_password,uuid,ss_key,sub_token,per_entry";

fn user_from_row(r: &rusqlite::Row) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        name: r.get(1)?,
        plan: r.get(2)?,
        quota_bytes: r.get(3)?,
        expire_at: r.get(4)?,
        reset_day: r.get(5)?,
        reset_period: r.get(6)?,
        reset_seq: r.get(7)?,
        enabled: r.get(8)?,
        anytls_password: r.get(9)?,
        uuid: r.get(10)?,
        ss_key: r.get(11)?,
        sub_token: r.get(12)?,
        per_entry: r.get(13)?,
    })
}

/// Everything needed to build node configs and the panel state.
#[derive(Default)]
pub struct World {
    pub nodes: Vec<Node>,
    pub exits: Vec<Exit>,
    pub rulesets: Vec<RuleSet>,
    pub rules: Vec<EntryRule>,
    pub users: Vec<User>,
    pub user_entries: HashMap<i64, Vec<i64>>,
    /// (node id, name, period) -> up + down
    pub usage: HashMap<(i64, String, String), i64>,
    /// Sums over `usage`, built on first use: summing per lookup made every
    /// config and panel refresh quadratic in the number of users.
    totals: OnceLock<UsageTotals>,
    pub tz: i64,
    /// ACME account email and Cloudflare API token (Zone DNS edit), shared
    /// by every node that requests certificates.
    pub acme_email: String,
    pub cf_token: String,
}

impl World {
    pub fn node(&self, id: i64) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }
    pub fn exit(&self, id: i64) -> Option<&Exit> {
        self.exits.iter().find(|e| e.id == id)
    }
    pub fn rules_of(&self, node: i64) -> impl Iterator<Item = &EntryRule> {
        self.rules.iter().filter(move |r| r.node_id == node)
    }
    /// Sum of a counter name for a period across nodes, optionally skipping one.
    pub fn used(&self, name: &str, period: &str, skip_node: Option<i64>) -> i64 {
        let total = self.totals().by_name.get(name).and_then(|p| p.get(period)).copied().unwrap_or(0);
        match skip_node {
            Some(n) => total.saturating_sub(self.own(n, name, period)),
            None => total,
        }
    }

    /// Sum of one node's counters for an exit in a period (the entries'
    /// "n<entry>x<exit>" counters on that exit's node).
    pub fn exit_used(&self, node: i64, exit: i64, period: &str) -> i64 {
        self.totals().by_exit.get(&(node, exit)).and_then(|p| p.get(period)).copied().unwrap_or(0)
    }

    /// One node's own figure for a counter in a period.
    pub fn own(&self, node: i64, name: &str, period: &str) -> i64 {
        self.usage.get(&(node, name.to_string(), period.to_string())).copied().unwrap_or(0)
    }

    fn totals(&self) -> &UsageTotals {
        self.totals.get_or_init(|| {
            let mut t = UsageTotals::default();
            for ((node, name, period), v) in &self.usage {
                t.add(*node, name, period, *v);
            }
            t
        })
    }
}

#[derive(Default)]
struct UsageTotals {
    /// name -> period -> sum over nodes
    by_name: HashMap<String, HashMap<String, i64>>,
    /// (node id, exit id) -> period -> sum of that node's counters for the exit
    by_exit: HashMap<(i64, i64), HashMap<String, i64>>,
}

impl UsageTotals {
    /// Adds one usage row (up + down already summed), saturating.
    fn add(&mut self, node: i64, name: &str, period: &str, v: i64) {
        fn sum(periods: &mut HashMap<String, i64>, period: &str, v: i64) {
            match periods.get_mut(period) {
                Some(s) => *s = s.saturating_add(v),
                None => {
                    periods.insert(period.to_owned(), v);
                }
            }
        }
        if !self.by_name.contains_key(name) {
            self.by_name.insert(name.to_owned(), HashMap::new());
        }
        sum(self.by_name.get_mut(name).expect("inserted"), period, v);
        if let Some(exit) = crate::nodecfg::counter_exit(name) {
            sum(self.by_exit.entry((node, exit)).or_default(), period, v);
        }
    }
}

pub fn load_world(conn: &Connection) -> rusqlite::Result<World> {
    let mut w = load_world_base(conn)?;
    // Periods are at most a month long; older rows only matter for history.
    let since = crate::period::now() - 70 * 86_400;
    // Summed here rather than in SQL: an overflowing up+down turns into a
    // REAL there, and one unreadable row must not take the whole world down.
    let mut st = conn.prepare("SELECT node_id,name,period,up,down FROM usage WHERE updated >= ?1")?;
    let rows = st.query_map([since], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?, r.get::<_, i64>(4)?))
    })?;
    for (n, name, period, up, down) in rows.flatten() {
        w.usage.insert((n, name, period), up.max(0).saturating_add(down.max(0)));
    }
    Ok(w)
}

/// load_world for the panel: the usage rows are summed as they are read,
/// with the same rules, so World::used and World::exit_used work but
/// World::own, which needs the rows, does not. Not for node configs.
/// Keeping a map entry per row was most of the cost of the panel's state.
pub fn load_world_summed(conn: &Connection) -> rusqlite::Result<World> {
    let w = load_world_base(conn)?;
    let since = crate::period::now() - 70 * 86_400;
    let mut totals = UsageTotals::default();
    let mut st = conn.prepare_cached("SELECT node_id,name,period,up,down FROM usage WHERE updated >= ?1")?;
    let mut rows = st.query([since])?;
    while let Some(r) = rows.next()? {
        let (Ok(node), Ok(name), Ok(period), Ok(up), Ok(down)) =
            (r.get::<_, i64>(0), r.get_ref(1).map(|v| v.as_str()), r.get_ref(2).map(|v| v.as_str()), r.get::<_, i64>(3), r.get::<_, i64>(4))
        else {
            continue;
        };
        let (Ok(name), Ok(period)) = (name, period) else { continue };
        totals.add(node, name, period, up.max(0).saturating_add(down.max(0)));
    }
    let _ = w.totals.set(totals);
    Ok(w)
}

/// Everything but the usage rows.
fn load_world_base(conn: &Connection) -> rusqlite::Result<World> {
    let mut w = World::default();
    w.tz = get_setting(conn, "tz_offset")?.and_then(|v| v.parse().ok()).unwrap_or(480);
    w.acme_email = get_setting(conn, "acme_email")?.unwrap_or_default();
    w.cf_token = get_setting(conn, "cf_token")?.unwrap_or_default();
    w.nodes = load_nodes(conn)?;
    w.exits = load_exits(conn)?;
    let mut st = conn.prepare("SELECT id,label,description,domains FROM rulesets ORDER BY sort, id")?;
    w.rulesets = st
        .query_map([], |r| Ok(RuleSet { id: r.get(0)?, label: r.get(1)?, description: r.get(2)?, domains: r.get(3)? }))?
        .collect::<Result<_, _>>()?;
    let mut st = conn.prepare("SELECT er.node_id,er.ruleset,er.exit_id,er.fallback FROM entry_rules er JOIN rulesets r ON r.id=er.ruleset ORDER BY r.sort")?;
    w.rules = st
        .query_map([], |r| Ok(EntryRule {
                node_id: r.get(0)?,
                ruleset: r.get(1)?,
                exit_id: r.get(2)?,
                fallback: ids_from_text(&r.get::<_, String>(3)?),
            }))?
        .collect::<Result<_, _>>()?;
    let mut st = conn.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY id"))?;
    w.users = st.query_map([], user_from_row)?.collect::<Result<_, _>>()?;
    let mut st = conn.prepare("SELECT user_id,node_id FROM user_entries")?;
    for row in st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))? {
        let (u, n) = row?;
        w.user_entries.entry(u).or_default().push(n);
    }
    Ok(w)
}

/// What one user's subscription needs, instead of the whole world: the
/// user's entries and the recent usage rows of their counter (on any node,
/// as World::used counts them).
pub fn load_user_world(conn: &Connection, user: &User) -> rusqlite::Result<World> {
    let mut w = World::default();
    w.tz = get_setting(conn, "tz_offset")?.and_then(|v| v.parse().ok()).unwrap_or(480);
    let mut st = conn.prepare_cached(&format!(
        "SELECT {NODE_COLS} FROM nodes WHERE id IN (SELECT node_id FROM user_entries WHERE user_id=?1) ORDER BY sort, id"
    ))?;
    w.nodes = st.query_map([user.id], node_from_row)?.collect::<Result<_, _>>()?;
    w.user_entries.insert(user.id, w.nodes.iter().map(|n| n.id).collect());
    let since = crate::period::now() - 70 * 86_400;
    let mut st = conn.prepare_cached("SELECT node_id,period,up,down FROM usage WHERE name=?1 AND updated >= ?2")?;
    let name = crate::nodecfg::user_counter(user.id);
    let rows = st.query_map(params![name, since], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)))?;
    for (n, period, up, down) in rows.flatten() {
        w.usage.insert((n, name.clone(), period), up.max(0).saturating_add(down.max(0)));
    }
    Ok(w)
}

/// Every node, in panel order.
pub fn load_nodes(conn: &Connection) -> rusqlite::Result<Vec<Node>> {
    let mut st = conn.prepare_cached(&format!("SELECT {NODE_COLS} FROM nodes ORDER BY sort, id"))?;
    let nodes = st.query_map([], node_from_row)?.collect();
    nodes
}

pub fn node_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<Node>> {
    conn.query_row(&format!("SELECT {NODE_COLS} FROM nodes WHERE id=?1"), [id], node_from_row).optional()
}

pub fn user_by_id(conn: &Connection, id: i64) -> rusqlite::Result<Option<User>> {
    conn.query_row(&format!("SELECT {USER_COLS} FROM users WHERE id=?1"), [id], user_from_row).optional()
}

/// Every exit, in panel order.
pub fn load_exits(conn: &Connection) -> rusqlite::Result<Vec<Exit>> {
    let mut st = conn.prepare_cached(&format!("SELECT {EXIT_COLS} FROM exits ORDER BY sort, id"))?;
    let exits = st.query_map([], exit_from_row)?.collect();
    exits
}

/// The SS 2022 ports an exit node serves, in panel order.
pub fn exits_of(conn: &Connection, node_id: i64) -> rusqlite::Result<Vec<Exit>> {
    let mut st = conn.prepare_cached(&format!("SELECT {EXIT_COLS} FROM exits WHERE node_id=?1 ORDER BY sort, id"))?;
    let exits = st.query_map([node_id], exit_from_row)?.collect();
    exits
}

const EXIT_COLS: &str = "id,COALESCE(node_id,0),name,port,psk,quota_bytes,reset_day,udp_over_tcp,sort,kind,server,uuid,method,pub_port,tls_sni,vless_opts";

fn exit_from_row(r: &rusqlite::Row) -> rusqlite::Result<Exit> {
    Ok(Exit {
        id: r.get(0)?,
        node_id: r.get(1)?,
        name: r.get(2)?,
        port: r.get(3)?,
        psk: r.get(4)?,
        quota_bytes: r.get(5)?,
        reset_day: r.get(6)?,
        udp_over_tcp: r.get(7)?,
        sort: r.get(8)?,
        kind: r.get(9)?,
        server: r.get(10)?,
        uuid: r.get(11)?,
        method: r.get(12)?,
        tls_sni: r.get(14)?,
        vless_opts: r.get(15)?,
        pub_port: r.get(13)?,
    })
}

pub fn node_by_token(conn: &Connection, token: &str) -> rusqlite::Result<Option<Node>> {
    conn.query_row(&format!("SELECT {NODE_COLS} FROM nodes WHERE token=?1"), [token], node_from_row).optional()
}

pub fn user_by_sub(conn: &Connection, token: &str) -> rusqlite::Result<Option<User>> {
    conn.query_row(&format!("SELECT {USER_COLS} FROM users WHERE sub_token=?1"), [token], user_from_row).optional()
}

pub fn insert_node(conn: &Connection, role: &str, code: &str, name: &str, now: i64) -> rusqlite::Result<i64> {
    let token = random_hex(24);
    let sort: i64 = conn.query_row("SELECT COALESCE(MAX(sort),0)+1 FROM nodes", [], |r| r.get(0))?;
    let id = fresh_id(conn, "nodes")?;
    if role == "entry" {
        let (private, public) = crate::util::reality_keypair();
        // Different entries borrow different sites, so the same camouflage
        // does not mark every keel entry. All serve TLS 1.3 with X25519.
        let dest = REALITY_DESTS[crate::util::random_bytes(1)[0] as usize % REALITY_DESTS.len()];
        let anytls_port = crate::util::random_port(&[]);
        let vless_port = crate::util::random_port(&[anytls_port]);
        conn.execute(
            "INSERT INTO nodes(code,name,role,token,sort,anytls_on,anytls_port,vless_on,vless_port,reality_dest,reality_sni,reality_private,reality_public,reality_short_id,ss_port,ss_psk,created_at,id)
             VALUES(?1,?2,'entry',?3,?4,1,?10,0,?11,?13,?14,?5,?6,?7,0,?8,?9,?12)",
            params![code, name, token, sort, private, public, random_hex(8), random_b64(16), now, anytls_port, vless_port, id, format!("{dest}:443"), dest],
        )?;
    } else {
        conn.execute(
            "INSERT INTO nodes(code,name,role,token,sort,created_at,id) VALUES(?1,?2,'exit',?3,?4,?5,?6)",
            params![code, name, token, sort, now, id],
        )?;
    }
    Ok(id)
}

/// Sites a new entry's REALITY inbound borrows (one at random), and the
/// candidates entries time so the panel can offer the nearest.
pub const REALITY_DESTS: &[&str] = &["www.apple.com", "www.microsoft.com", "www.amazon.com", "www.cloudflare.com", "www.samsung.com", "www.nvidia.com"];

/// A new user never gets a deleted user's id: usage is stored by the
/// counter name u<id>, which would carry over.
pub fn insert_user(conn: &Connection, name: &str, now: i64) -> rusqlite::Result<i64> {
    let id = fresh_id(conn, "users")?;
    conn.execute(
        "INSERT INTO users(id,name,anytls_password,uuid,ss_key,sub_token,created_at,per_entry) VALUES(?7,?1,?2,?3,?4,?5,?6,1)",
        params![name, random_hex(16), random_uuid(), random_b64(16), random_hex(16), now, id],
    )?;
    Ok(id)
}

/// Counter names a node may report: the users the master gives an entry,
/// or the per-entry counters of an exit node's own ports.
pub fn node_counters(conn: &Connection, node: i64) -> rusqlite::Result<std::collections::HashSet<String>> {
    let mut st = conn.prepare(
        "SELECT 'u' || user_id FROM user_entries WHERE node_id=?1
         UNION SELECT 'n' || n.id || 'x' || e.id FROM exits e, nodes n WHERE e.node_id=?1 AND n.role='entry'",
    )?;
    let rows = st.query_map([node], |r| r.get::<_, String>(0))?;
    rows.collect()
}

/// Stores the absolute counters from a node report. Within a period they only
/// grow: a node that crashed before saving reports less than it had.
///
/// One transaction per report, and a counter that did not grow is not
/// rewritten: every row in its own commit rewrote every counter of every
/// node every 5 s, traffic or not.
pub fn store_usage(conn: &Connection, node: i64, rows: &[(String, String, i64, i64)], now: i64) -> rusqlite::Result<()> {
    let tx = conn.unchecked_transaction()?;
    {
        let mut st = tx.prepare_cached(
            "INSERT INTO usage(node_id,name,period,up,down,updated) VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(node_id,name,period) DO UPDATE SET up=MAX(up,excluded.up), down=MAX(down,excluded.down), updated=excluded.updated
             WHERE excluded.up > usage.up OR excluded.down > usage.down",
        )?;
        for (name, period, up, down) in rows {
            st.execute(params![node, name, period, up, down, now])?;
        }
    }
    tx.commit()
}

pub fn add_node_month(conn: &Connection, node: i64, month: &str, rx: i64, tx: i64) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO node_month(node_id,month,rx,tx) VALUES(?1,?2,?3,?4)
         ON CONFLICT(node_id,month) DO UPDATE SET rx=rx+excluded.rx, tx=tx+excluded.tx",
        params![node, month, rx, tx],
    )?;
    Ok(())
}

pub fn node_months(conn: &Connection, month: &str) -> rusqlite::Result<HashMap<i64, (i64, i64)>> {
    // Totals that once overflowed into REAL are read back clamped.
    let mut st = conn.prepare(
        "SELECT node_id,CAST(MAX(0,MIN(rx,9e18)) AS INTEGER),CAST(MAX(0,MIN(tx,9e18)) AS INTEGER) FROM node_month WHERE month=?1",
    )?;
    let rows = st.query_map([month], |r| Ok((r.get::<_, i64>(0)?, (r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))))?;
    rows.collect()
}

pub fn prune(conn: &Connection, now: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM usage WHERE updated < ?1", [now - 400 * 86_400])?;
    conn.execute("DELETE FROM sessions WHERE expires < ?1", [now])?;
    Ok(())
}

impl Node {
    /// The name clients check the AnyTLS certificate against.
    pub fn anytls_name(&self) -> &str {
        if self.anytls_sni.is_empty() {
            self.address()
        } else {
            &self.anytls_sni
        }
    }

    /// Whether the entry serves the master-made self-signed certificate.
    pub fn anytls_self_signed(&self) -> bool {
        !self.anytls_acme && (self.anytls_cert.is_empty() || self.anytls_key.is_empty()) && !self.anytls_self_cert.is_empty()
    }
}

/// Makes or renews the self-signed AnyTLS certificate of every entry that
/// needs one: a neutral subject for the name clients use, valid for a year
/// or two, renewed each new year and whenever that name changes.
pub fn ensure_self_certs(conn: &Connection) -> rusqlite::Result<()> {
    let year = 1970 + (crate::period::now() / 31_556_952) as i32;
    let mut st = conn.prepare(&format!("SELECT {NODE_COLS}, anytls_self_name FROM nodes WHERE role='entry' AND anytls_on=1"))?;
    let rows: Vec<(Node, String)> = st.query_map([], |r| Ok((node_from_row(r)?, r.get(35)?)))?.collect::<Result<_, _>>()?;
    for (n, made) in rows {
        let wanted = format!("{}|{year}", n.anytls_name());
        let uses_own = !n.anytls_acme && (n.anytls_cert.is_empty() || n.anytls_key.is_empty());
        if !uses_own || n.anytls_name().is_empty() || made == wanted {
            continue;
        }
        let Ok((cert, key)) = self_signed(n.anytls_name(), year) else { continue };
        conn.execute(
            "UPDATE nodes SET anytls_self_cert=?1, anytls_self_key=?2, anytls_self_name=?3 WHERE id=?4",
            params![cert, key, wanted, n.id],
        )?;
    }
    Ok(())
}

fn self_signed(name: &str, year: i32) -> Result<(String, String), rcgen::Error> {
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![name.to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(rcgen::DnType::CommonName, name);
    params.not_before = rcgen::date_time_ymd(year, 1, 1);
    params.not_after = rcgen::date_time_ymd(year + 2, 1, 1);
    let cert = params.self_signed(&key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// SHA-256 of a PEM certificate's DER, as lowercase hex.
pub fn cert_sha256(pem: &str) -> Option<String> {
    let der = rustls_pemfile::certs(&mut pem.as_bytes()).next()?.ok()?;
    Some(crate::util::hex(&crate::util::sha256(der.as_ref())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_totals_match_a_plain_sum() {
        let mut w = World::default();
        let mut seed: u64 = 7;
        let mut next = |m: u64| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (seed >> 33) % m
        };
        let names: Vec<String> = (1..=6).map(|i| format!("u{i}")).chain((1..=3).map(|i| format!("n{i}x9"))).chain(["n1x8".into(), "bad".into()]).collect();
        let periods = ["2026-10-01", "2026-09-01", "2026-10-01#1"];
        for node in 1..=5 {
            for name in &names {
                for p in periods {
                    if next(3) > 0 {
                        w.usage.insert((node, name.clone(), p.to_string()), next(1 << 40) as i64);
                    }
                }
            }
        }
        let plain = |name: &str, period: &str, skip: Option<i64>| -> i64 {
            w.usage.iter().filter(|((n, nm, p), _)| nm == name && p == period && Some(*n) != skip).map(|(_, v)| *v).sum()
        };
        let plain_exit = |node: i64, exit: i64, period: &str| -> i64 {
            w.usage
                .iter()
                .filter(|((n, nm, p), _)| *n == node && p == period && crate::nodecfg::counter_exit(nm) == Some(exit))
                .map(|(_, v)| *v)
                .sum()
        };
        for name in &names {
            for p in periods {
                for skip in [None, Some(1), Some(3), Some(9)] {
                    assert_eq!(w.used(name, p, skip), plain(name, p, skip), "{name} {p} {skip:?}");
                }
            }
        }
        for node in 0..=6 {
            for exit in [8, 9, 10] {
                for p in periods {
                    assert_eq!(w.exit_used(node, exit, p), plain_exit(node, exit, p), "{node} {exit} {p}");
                }
            }
        }
        assert_eq!(w.used("u404", "2026-10-01", None), 0);
    }

    #[test]
    fn store_usage_only_rewrites_counters_that_grew() {
        let path = std::env::temp_dir().join(format!("keel-db-test-{}-{}.db", std::process::id(), random_hex(4)));
        let conn = open(&path).unwrap();
        let read = |conn: &Connection| -> (i64, i64, i64) {
            conn.query_row("SELECT up,down,updated FROM usage WHERE node_id=1 AND name='u1' AND period='p'", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap()
        };
        let row = |up: i64, down: i64| vec![("u1".to_string(), "p".to_string(), up, down)];
        store_usage(&conn, 1, &row(10, 20), 100).unwrap();
        assert_eq!(read(&conn), (10, 20, 100));
        store_usage(&conn, 1, &row(10, 20), 200).unwrap(); // unchanged: not rewritten
        assert_eq!(read(&conn), (10, 20, 100));
        store_usage(&conn, 1, &row(11, 20), 300).unwrap(); // grew
        assert_eq!(read(&conn), (11, 20, 300));
        store_usage(&conn, 1, &row(5, 25), 400).unwrap(); // up fell back (crash), down grew: keep the larger of each
        assert_eq!(read(&conn), (11, 25, 400));
        store_usage(&conn, 1, &row(1, 1), 500).unwrap(); // both lower: nothing changes
        assert_eq!(read(&conn), (11, 25, 400));
        drop(conn);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn summed_world_matches_the_full_one() {
        let path = std::env::temp_dir().join(format!("keel-db-test-{}-{}.db", std::process::id(), random_hex(4)));
        let conn = open(&path).unwrap();
        let ts = crate::period::now();
        let exit = crate::nodecfg::exit_counter(1, 2);
        store_usage(&conn, 1, &[("u1".into(), "p".into(), 5, 7), (exit.clone(), "p".into(), 1, 2)], ts).unwrap();
        store_usage(&conn, 2, &[("u1".into(), "p".into(), i64::MAX, 1), ("u1".into(), "q".into(), 3, 0)], ts).unwrap();
        // An unreadable row is skipped by both.
        conn.execute("INSERT INTO usage(node_id,name,period,up,down,updated) VALUES(3,'u1','p',1e30,0,?1)", [ts]).unwrap();
        let (full, summed) = (load_world(&conn).unwrap(), load_world_summed(&conn).unwrap());
        for (name, period) in [("u1", "p"), ("u1", "q"), (exit.as_str(), "p"), ("u9", "p")] {
            assert_eq!(full.used(name, period, None), summed.used(name, period, None), "{name} {period}");
        }
        assert_eq!(summed.used("u1", "p", None), i64::MAX);
        assert_eq!(full.exit_used(1, 2, "p"), summed.exit_used(1, 2, "p"));
        assert_eq!(summed.exit_used(1, 2, "p"), 3);
        drop(conn);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn a_report_leaving_a_user_out_keeps_their_counters() {
        // Delta reports only list the users that changed: one left out keeps
        // what is stored, it never counts as zero.
        let path = std::env::temp_dir().join(format!("keel-db-test-{}-{}.db", std::process::id(), random_hex(4)));
        let conn = open(&path).unwrap();
        let ts = crate::period::now();
        let rows = |list: &[(&str, i64)]| list.iter().map(|&(name, down)| (name.to_string(), "p".to_string(), 0, down)).collect::<Vec<_>>();
        store_usage(&conn, 1, &rows(&[("u1", 10), ("u2", 20)]), ts).unwrap();
        store_usage(&conn, 1, &rows(&[("u1", 15)]), ts + 5).unwrap();
        let w = load_world(&conn).unwrap();
        assert_eq!(w.used("u1", "p", None), 15);
        assert_eq!(w.used("u2", "p", None), 20);
        drop(conn);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
