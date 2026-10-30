#!/usr/bin/env python3
"""Seed a keel-master database (created by keel-master itself, so the schema
and migrations are in place) with nodes, exits, rules, users, user_entries,
usage history and node_month rows.

usage: seed.py DB ENTRIES EXIT_NODES USERS PERIODS [ENTRIES_PER_USER]

PERIODS = how many accounting periods of usage history per (entry, user)
pair, the current one included (12 = about a year of operation).
ENTRIES_PER_USER defaults to all entries (the panel's default for new users).
"""
import base64, os, random, secrets, sqlite3, sys, time, uuid

random.seed(42)
db, E, X, U, P = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
EPU = int(sys.argv[6]) if len(sys.argv) > 6 else E
TZ = 480
NOW = int(time.time())


def days_from_civil(y, m, d):
    y = y - 1 if m <= 2 else y
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m - 3 if m > 2 else m + 9) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def civil_from_days(z):
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    return (y + 1 if m <= 2 else y, m, d)


def dim(y, m):
    ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
    return days_from_civil(ny, nm, 1) - days_from_civil(y, m, 1)


def local_date(ts):
    return civil_from_days((ts + TZ * 60) // 86400)


def period_start(ts, day):
    day = max(1, min(31, day))
    y, m, d = local_date(ts)
    this = min(day, dim(y, m))
    if d >= this:
        return (y, m, this)
    py, pm = (y - 1, 12) if m == 1 else (y, m - 1)
    return (py, pm, min(day, dim(py, pm)))


def start_ts(ymd):
    return days_from_civil(*ymd) * 86400 - TZ * 60


def periods(day, n):
    """[(label, updated_ts)] for the current and n-1 previous periods."""
    out = []
    ts = NOW
    for k in range(n):
        ymd = period_start(ts, day)
        label = "%04d-%02d-%02d" % ymd
        upd = NOW - random.randint(0, 300) if k == 0 else ts  # last update = end of that period
        out.append((label, upd))
        ts = start_ts(ymd) - 1
    return out


def b64(n):
    return base64.b64encode(secrets.token_bytes(n)).decode()


def b64url(n):
    return base64.urlsafe_b64encode(secrets.token_bytes(n)).decode().rstrip("=")


conn = sqlite3.connect(db)
conn.execute("PRAGMA foreign_keys=ON")
cur = conn.cursor()
cur.execute("BEGIN")
for t in ["usage", "node_month", "user_entries", "users", "entry_rules", "exits", "nodes"]:
    cur.execute(f"DELETE FROM {t}")

entry_ids = list(range(1, E + 1))
exitnode_ids = list(range(E + 1, E + X + 1))
nodes = []
for i, nid in enumerate(entry_ids + exitnode_ids):
    role = "entry" if nid in entry_ids else "exit"
    host = "198.51.100.%d" % (nid % 250 + 1) if nid < 251 else "203.0.113.%d" % (nid % 250 + 1)
    nodes.append((nid, "N%03d" % nid, ("入口" if role == "entry" else "出口") + str(nid), role, host, "127.0.0.1",
                  secrets.token_hex(24), i, 1, "", 1 if role == "entry" else 0, 20000 + nid, "",
                  1 if role == "entry" else 0, 30000 + nid, "www.apple.com:443", "www.apple.com", b64url(32), b64url(32),
                  secrets.token_hex(8), 0, 0, b64(16), 0, NOW))
cur.executemany(
    "INSERT INTO nodes(id,code,name,role,host,last_ip,token,sort,ipv4_only,direct_list,anytls_on,anytls_port,anytls_sni,"
    "vless_on,vless_port,reality_dest,reality_sni,reality_private,reality_public,reality_short_id,ss_on,ss_port,ss_psk,default_exit,created_at)"
    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", nodes)

# One SS-2022 port per exit node; exit id = 1000 + node id.
exits = []
for i, nid in enumerate(exitnode_ids):
    exits.append((1000 + nid, nid, "出口%d" % nid, 40000 + nid, b64(16), (2 << 40) if i % 2 == 0 else 0, 1 + i % 28, 0, i, "ss"))
cur.executemany("INSERT INTO exits(id,node_id,name,port,psk,quota_bytes,reset_day,udp_over_tcp,sort,kind) VALUES(?,?,?,?,?,?,?,?,?,?)", exits)
exit_ids = [e[0] for e in exits]

# Routing: default exit plus a fallback, AI and streaming to other exits.
for k, nid in enumerate(entry_ids):
    if not exit_ids:
        break
    d = exit_ids[k % len(exit_ids)]
    fb = exit_ids[(k + 1) % len(exit_ids)]
    cur.execute("UPDATE nodes SET default_exit=?, default_fallback=? WHERE id=?", (d, "%d,0" % fb, nid))
    cur.execute("INSERT INTO entry_rules(node_id,ruleset,exit_id,sort,fallback) VALUES(?,?,?,?,?)", (nid, "ai", exit_ids[(k + 2) % len(exit_ids)], 0, str(d)))
    cur.execute("INSERT INTO entry_rules(node_id,ruleset,exit_id,sort,fallback) VALUES(?,?,?,?,?)", (nid, "streaming", exit_ids[(k + 3) % len(exit_ids)], 1, ""))

users = []
for uid in range(1, U + 1):
    quota = 100 * (1 << 30) if uid % 10 else 0  # the panel suggests 100 GB
    expire = NOW + 180 * 86400 if uid % 3 == 0 else 0
    users.append((uid, "user%d" % uid, "", quota, expire, 1 + uid % 28, 1 if uid % 20 else 0,
                  secrets.token_hex(16), str(uuid.uuid4()), b64(16), secrets.token_hex(16), NOW))
cur.executemany("INSERT INTO users(id,name,plan,quota_bytes,expire_at,reset_day,enabled,anytls_password,uuid,ss_key,sub_token,created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", users)

ue = []
for uid in range(1, U + 1):
    chosen = entry_ids if EPU >= E else random.sample(entry_ids, EPU)
    for nid in chosen:
        ue.append((uid, nid))
cur.executemany("INSERT INTO user_entries(user_id,node_id) VALUES(?,?)", ue)

# Usage: what entries report per user, what exits report per entry counter.
usage = []
per_user = {}
for uid in range(1, U + 1):
    per_user[uid] = periods(1 + uid % 28, P)
for uid, nid in ue:
    for label, upd in per_user[uid]:
        usage.append((nid, "u%d" % uid, label, random.randint(0, 300 << 20), random.randint(0, 3 << 30), upd))
for e in exits:
    for label, upd in periods(e[6], P):
        for en in entry_ids:
            usage.append((e[1], "n%dx%d" % (en, e[0]), label, random.randint(0, 50 << 30), random.randint(0, 500 << 30), upd))
# Insert in the order a running master would have: rows appear when a period
# starts (period label), node by node.
usage.sort(key=lambda r: (r[2], r[0], r[1]))
cur.executemany("INSERT INTO usage(node_id,name,period,up,down,updated) VALUES(?,?,?,?,?,?)", usage)

months = []
y, m, _ = local_date(NOW)
for k in range(max(P, 1)):
    for nid in entry_ids + exitnode_ids:
        months.append((nid, "%04d-%02d" % (y, m), random.randint(0, 1 << 42), random.randint(0, 1 << 42)))
    y, m = (y - 1, 12) if m == 1 else (y, m - 1)
cur.executemany("INSERT INTO node_month(node_id,month,rx,tx) VALUES(?,?,?,?)", months)

for key, val in [("last_nodes_id", E + X), ("last_exits_id", max(exit_ids or [0])), ("last_users_id", U)]:
    cur.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(val)))
conn.commit()
loaded = sum(1 for r in usage if r[5] >= NOW - 70 * 86400)
print(f"nodes={E}+{X} exits={len(exits)} users={U} user_entries={len(ue)} usage_rows={len(usage)} (loaded by load_world: {loaded}) node_month={len(months)}")
conn.execute("VACUUM")
conn.close()
