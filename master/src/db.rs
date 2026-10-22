//! SQLite store. Everything the panel edits lives here; live probe data does
//! not (see live.rs). The data set is small (a handful of nodes, tens of
//! users), so callers load the whole world and work on it in memory.

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

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
  node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  port INTEGER NOT NULL,
  psk TEXT NOT NULL,
  quota_bytes INTEGER NOT NULL DEFAULT 0,
  reset_day INTEGER NOT NULL DEFAULT 1,
  udp_over_tcp INTEGER NOT NULL DEFAULT 0,
  sort INTEGER NOT NULL DEFAULT 0
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
];

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
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(SCHEMA)?;
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

#[derive(Clone, Debug, Serialize)]
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
    pub vless_on: bool,
    pub vless_port: i64,
    pub reality_dest: String,
    pub reality_sni: String,
    #[serde(skip)]
    pub reality_private: String,
    pub reality_public: String,
    pub reality_short_id: String,
    pub ss_on: bool,
    pub ss_port: i64,
    #[serde(skip)]
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
    /// Address clients and entries use to reach this node.
    pub fn address(&self) -> &str {
        if self.host.is_empty() {
            &self.last_ip
        } else {
            &self.host
        }
    }
}

const NODE_COLS: &str = "id,code,name,role,host,last_ip,token,sort,ipv4_only,direct_list,anytls_on,anytls_port,anytls_sni,vless_on,vless_port,reality_dest,reality_sni,reality_private,reality_public,reality_short_id,ss_on,ss_port,ss_psk,default_exit,config_rev,default_fallback";

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
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct Exit {
    pub id: i64,
    pub node_id: i64,
    pub name: String,
    pub port: i64,
    #[serde(skip)]
    pub psk: String,
    pub quota_bytes: i64,
    pub reset_day: i64,
    pub udp_over_tcp: bool,
    pub sort: i64,
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
}

const USER_COLS: &str = "id,name,plan,quota_bytes,expire_at,reset_day,reset_period,reset_seq,enabled,anytls_password,uuid,ss_key,sub_token";

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
    pub tz: i64,
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
        self.usage
            .iter()
            .filter(|((n, nm, p), _)| nm == name && p == period && Some(*n) != skip_node)
            .map(|(_, v)| *v)
            .sum()
    }
}

pub fn load_world(conn: &Connection) -> rusqlite::Result<World> {
    let mut w = World::default();
    w.tz = get_setting(conn, "tz_offset")?.and_then(|v| v.parse().ok()).unwrap_or(480);
    let mut st = conn.prepare(&format!("SELECT {NODE_COLS} FROM nodes ORDER BY sort, id"))?;
    w.nodes = st.query_map([], node_from_row)?.collect::<Result<_, _>>()?;
    let mut st = conn.prepare("SELECT id,node_id,name,port,psk,quota_bytes,reset_day,udp_over_tcp,sort FROM exits ORDER BY sort, id")?;
    w.exits = st
        .query_map([], |r| {
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
            })
        })?
        .collect::<Result<_, _>>()?;
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
    // Periods are at most a month long; older rows only matter for history.
    let since = crate::period::now() - 70 * 86_400;
    let mut st = conn.prepare("SELECT node_id,name,period,up+down FROM usage WHERE updated >= ?1")?;
    for row in st.query_map([since], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)))? {
        let (n, name, period, v) = row?;
        w.usage.insert((n, name, period), v);
    }
    Ok(w)
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
    if role == "entry" {
        let (private, public) = crate::util::reality_keypair();
        conn.execute(
            "INSERT INTO nodes(code,name,role,token,sort,anytls_on,anytls_port,vless_on,vless_port,reality_dest,reality_sni,reality_private,reality_public,reality_short_id,ss_port,ss_psk,created_at)
             VALUES(?1,?2,'entry',?3,?4,1,443,0,8443,'www.apple.com:443','www.apple.com',?5,?6,?7,8388,?8,?9)",
            params![code, name, token, sort, private, public, random_hex(8), random_b64(16), now],
        )?;
    } else {
        conn.execute(
            "INSERT INTO nodes(code,name,role,token,sort,created_at) VALUES(?1,?2,'exit',?3,?4,?5)",
            params![code, name, token, sort, now],
        )?;
    }
    Ok(conn.last_insert_rowid())
}

pub fn insert_user(conn: &Connection, name: &str, now: i64) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO users(name,anytls_password,uuid,ss_key,sub_token,created_at) VALUES(?1,?2,?3,?4,?5,?6)",
        params![name, random_hex(16), random_uuid(), random_b64(16), random_hex(16), now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Stores the absolute counters from a node report.
pub fn store_usage(conn: &Connection, node: i64, rows: &[(String, String, i64, i64)], now: i64) -> rusqlite::Result<()> {
    let mut st = conn.prepare_cached(
        "INSERT INTO usage(node_id,name,period,up,down,updated) VALUES(?1,?2,?3,?4,?5,?6)
         ON CONFLICT(node_id,name,period) DO UPDATE SET up=excluded.up, down=excluded.down, updated=excluded.updated",
    )?;
    for (name, period, up, down) in rows {
        st.execute(params![node, name, period, up, down, now])?;
    }
    Ok(())
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
    let mut st = conn.prepare("SELECT node_id,rx,tx FROM node_month WHERE month=?1")?;
    let rows = st.query_map([month], |r| Ok((r.get::<_, i64>(0)?, (r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))))?;
    rows.collect()
}

pub fn prune(conn: &Connection, now: i64) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM usage WHERE updated < ?1", [now - 400 * 86_400])?;
    conn.execute("DELETE FROM sessions WHERE expires < ?1", [now])?;
    Ok(())
}
