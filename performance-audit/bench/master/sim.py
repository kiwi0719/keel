#!/usr/bin/env python3
"""Simulates keel-node control connections (docs/node-protocol.md).

sim.py --port 18444 --db large/keel.db [--roles entry,exit] [--limit N] [--duration 120]
       [--traffic 0.2] [--interval 5] [--stats out.json] [--node old|new]

Each simulated node: dials wss://127.0.0.1:PORT/api/node/ws with its token,
sends hello (config_rev 0), answers every config with applied, and sends a
report every --interval seconds listing every user/counter of its config
(as keel-node does), with up/down growing for a --traffic fraction of them,
system stats, outbound health for each outbound in its config, and a probe
round every 6th report on entries.

--node new acts as a current keel-node: its hello offers usage_msg, and once
a config or usage message carries report_delta it reports only the users
that changed, with a full report first on each connection and every 5
minutes. --node old (the
default) reports every user every time and ignores usage messages.
"""
import argparse, asyncio, json, random, sqlite3, ssl, statistics, sys, time
from websockets.asyncio.client import connect

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--db", required=True)
ap.add_argument("--roles", default="entry,exit")
ap.add_argument("--limit", type=int, default=0)
ap.add_argument("--duration", type=float, default=60)
ap.add_argument("--traffic", type=float, default=0.2)
ap.add_argument("--interval", type=float, default=5)
ap.add_argument("--stats", default="")
ap.add_argument("--quiet", action="store_true")
ap.add_argument("--node", choices=["old", "new"], default="old")
a = ap.parse_args()

roles = a.roles.split(",")
con = sqlite3.connect(a.db)
rows = con.execute("SELECT id, role, token FROM nodes ORDER BY id").fetchall()
con.close()
rows = [r for r in rows if r[1] in roles]
if a.limit:
    rows = rows[: a.limit]

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
T0 = time.monotonic()
stats = {}


async def node(nid, role, token):
    st = stats[nid] = {"role": role, "configs": [], "first_config_s": None, "open_s": None, "reports": 0, "report_bytes": 0,
                       "usage_msgs": 0, "usage_bytes": 0, "report_users": 0, "full_reports": 0, "errors": []}
    t_start = time.monotonic()
    try:
        async with connect(f"wss://127.0.0.1:{a.port}/api/node/ws", additional_headers={"Authorization": f"Bearer {token}"},
                           ssl=ctx, max_size=None, ping_interval=30, open_timeout=120, close_timeout=2, compression=None) as ws:
            st["open_s"] = time.monotonic() - t_start
            t_hello = time.monotonic()
            await ws.send(json.dumps({"type": "hello", "node_version": "sim", "protocols": ["anytls", "vless", "ss2022"],
                                      "hostname": f"sim{nid}", "os": "linux", "arch": "amd64", "config_rev": 0,
                                      "features": ["spki_pin", "usage_msg"] if a.node == "new" else []}))
            state = {"users": [], "rev": 0, "outbounds": [], "counters": {}, "delta": False}
            got_config = asyncio.Event()

            async def reader():
                async for msg in ws:
                    t = time.monotonic()
                    v = json.loads(msg)
                    if v.get("type") == "config":
                        if st["first_config_s"] is None:
                            st["first_config_s"] = t - t_hello
                        st["configs"].append([round(t - T0, 3), len(msg)])
                        cfg = v["config"]
                        users = []
                        for u in cfg.get("users", []):
                            users.append((u["name"], u["period"]))
                            key = (u["name"], u["period"])
                            if key not in state["counters"]:
                                state["counters"][key] = [0, int(u.get("used_self", 0))]
                        state["users"] = users
                        state["rev"] = v["rev"]
                        state["outbounds"] = [o["tag"] for o in cfg.get("outbounds", [])]
                        state["delta"] = a.node == "new" and bool(v.get("report_delta"))
                        got_config.set()
                        await ws.send(json.dumps({"type": "applied", "rev": v["rev"]}))
                    elif v.get("type") == "usage" and a.node == "new":
                        st["usage_msgs"] += 1
                        st["usage_bytes"] += len(msg)
                        state["delta"] = bool(v.get("report_delta"))

            async def reporter():
                await got_config.wait()
                await asyncio.sleep(random.uniform(0, a.interval))
                n = 0
                net = [random.randint(1 << 30, 1 << 40), random.randint(1 << 30, 1 << 40)]
                sent, last_full = {}, -1e9
                while True:
                    n += 1
                    users = []
                    for name, period in state["users"]:
                        c = state["counters"][(name, period)]
                        active = random.random() < a.traffic
                        if active:
                            c[0] += random.randint(1, 1 << 20)
                            c[1] += random.randint(1, 10 << 20)
                        users.append({"name": name, "period": period, "up": c[0], "down": c[1],
                                      "conns": random.randint(1, 4) if active else 0, "blocked": False})
                    full = not state["delta"] or time.monotonic() - last_full >= 300
                    if full:
                        last_full = time.monotonic()
                        sent = {u["name"]: u for u in users}
                    else:
                        changed = [u for u in users if sent.get(u["name"]) != u]
                        for u in changed:
                            sent[u["name"]] = u
                        users = changed
                    net[0] += random.randint(0, 50 << 20)
                    net[1] += random.randint(0, 50 << 20)
                    rep = {"type": "report", "ts": int(time.time()), "config_rev": state["rev"], "full": full, "users": users,
                           "system": {"cpu_pct": random.uniform(1, 30), "load1": 0.3, "mem_total": 1 << 30, "mem_used": 300 << 20,
                                      "swap_total": 0, "swap_used": 0, "disk_total": 20 << 30, "disk_used": 5 << 30,
                                      "net_rx": net[0], "net_tx": net[1], "rx_rate": random.uniform(1e5, 1e7), "tx_rate": random.uniform(1e5, 1e7),
                                      "tcp_conns": 100, "udp_conns": 10, "uptime_s": 86400, "rss": 20 << 20, "tcp_retrans_pct": 0.3},
                           "outbounds": [{"tag": t, "alive": True, "latency_ms": random.uniform(50, 300), "checked_at": int(time.time())} for t in state["outbounds"]]}
                    if role == "entry" and n % 6 == 1:
                        at = int(time.time())
                        rep["probes"] = [{"name": p, "host": "203.0.113.1:80", "latency_ms": random.uniform(20, 80), "jitter_ms": 2.0,
                                          "loss_pct": 0, "samples": 10, "at": at} for p in ("ct", "cu", "cm")]
                    body = json.dumps(rep)
                    await ws.send(body)
                    st["report_users"] += len(users)
                    st["full_reports"] += full
                    st["reports"] += 1
                    st["report_bytes"] += len(body)
                    await asyncio.sleep(a.interval)

            tasks = [asyncio.create_task(reader()), asyncio.create_task(reporter())]
            remaining = a.duration - (time.monotonic() - T0)
            done, pending = await asyncio.wait(tasks, timeout=max(remaining, 0.1), return_when=asyncio.FIRST_EXCEPTION)
            for t in pending:
                t.cancel()
            for t in done:
                if t.exception():
                    st["errors"].append(repr(t.exception()))
    except Exception as e:  # noqa
        st["errors"].append(repr(e))


async def main():
    await asyncio.gather(*(node(nid, role, tok) for nid, role, tok in rows))


asyncio.run(main())
el = time.monotonic() - T0
fc = [s["first_config_s"] for s in stats.values() if s["first_config_s"] is not None]
nconf = sum(len(s["configs"]) for s in stats.values())
bconf = sum(c[1] for s in stats.values() for c in s["configs"])
rep = sum(s["reports"] for s in stats.values())
rb = sum(s["report_bytes"] for s in stats.values())
errs = [(nid, s["errors"]) for nid, s in stats.items() if s["errors"]]
sizes = sorted(c[1] for s in stats.values() for c in s["configs"])
print(f"nodes={len(rows)} elapsed={el:.1f}s first_config: n={len(fc)} min={min(fc) if fc else 0:.3f}s median={statistics.median(fc) if fc else 0:.3f}s max={max(fc) if fc else 0:.3f}s")
um = sum(s["usage_msgs"] for s in stats.values())
ub = sum(s["usage_bytes"] for s in stats.values())
print(f"configs_received={nconf} bytes={bconf/1048576:.2f}MB size_min={sizes[0] if sizes else 0} size_max={sizes[-1] if sizes else 0} reports_sent={rep} report_bytes={rb/1048576:.2f}MB errors={len(errs)}")
ru = sum(s["report_users"] for s in stats.values())
fr = sum(s["full_reports"] for s in stats.values())
print(f"usage_msgs={um} usage_bytes={ub/1048576:.3f}MB users_per_report={ru / max(rep, 1):.1f} full_reports={fr}")
if errs and not a.quiet:
    print("errors:", errs[:5])
if a.stats:
    json.dump(stats, open(a.stats, "w"))
