#!/usr/bin/env python3
"""Replays one node report's usage upserts (db::store_usage) against a copy of
a seeded database, with the master's pragmas, three ways:
  autocommit  - one implicit transaction per row (what store_usage does now)
  one_tx      - the same statements inside BEGIN/COMMIT
  one_tx_skip - one transaction, and rows whose counters did not grow are not rewritten
Counts WAL frames written (autocheckpoint off, so frames accumulate) and time.

usage: wal_bench.py SRC_DB NODE_ID REPEATS
"""
import shutil, sqlite3, sys, time, os, random

src, node, reps = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
dst = os.path.join(os.path.dirname(os.path.abspath(src)), "..", "walbench.db")
dst = os.path.abspath(dst)
for suffix in ("", "-wal", "-shm"):
    try:
        os.remove(dst + suffix)
    except FileNotFoundError:
        pass
shutil.copy(src, dst)

UPSERT = ("INSERT INTO usage(node_id,name,period,up,down,updated) VALUES(?1,?2,?3,?4,?5,?6) "
          "ON CONFLICT(node_id,name,period) DO UPDATE SET up=MAX(up,excluded.up), down=MAX(down,excluded.down), updated=excluded.updated")
UPSERT_SKIP = UPSERT + " WHERE excluded.up>up OR excluded.down>down"

c = sqlite3.connect(dst, isolation_level=None)
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA synchronous=NORMAL")
c.execute("PRAGMA foreign_keys=ON")
c.execute("PRAGMA busy_timeout=5000")
c.execute("PRAGMA wal_autocheckpoint=0")

# The rows this node reports: its current-period counters (max period per name).
rows = c.execute("SELECT name, MAX(period), up, down FROM usage WHERE node_id=? GROUP BY name", (node,)).fetchall()
print(f"node {node}: {len(rows)} counters per report")


def frames():
    # (busy, frames in WAL, frames checkpointed); then reset the WAL.
    r = c.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    return r[1]


def run(mode, active_frac):
    frames()
    t = time.perf_counter()
    for rep in range(reps):
        now = int(time.time()) + rep
        data = []
        for name, period, up, down in rows:
            if random.random() < active_frac:
                up += random.randint(1, 1 << 20)
                down += random.randint(1, 10 << 20)
            data.append((node, name, period, up, down, now))
        if mode == "autocommit":
            c.executemany(UPSERT, data)  # isolation_level=None: each row commits on its own
        else:
            c.execute("BEGIN")
            c.executemany(UPSERT if mode == "one_tx" else UPSERT_SKIP, data)
            c.execute("COMMIT")
        # carry the growth forward like a real node
        rows[:] = [(d[1], d[2], d[3], d[4]) for d in data]
    el = time.perf_counter() - t
    f = frames()
    print(f"{mode:12s} active={active_frac:.1f}: {el/reps*1000:8.2f} ms/report, {f/reps:8.1f} WAL frames/report = {f*4096/reps/1048576:6.2f} MB/report")


for frac in (0.2, 0.0):
    for mode in ("autocommit", "one_tx", "one_tx_skip"):
        run(mode, frac)
c.close()
for suffix in ("", "-wal", "-shm"):
    try:
        os.remove(dst + suffix)
    except FileNotFoundError:
        pass
