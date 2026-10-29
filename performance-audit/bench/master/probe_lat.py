#!/usr/bin/env python3
"""probe_lat.py URL INTERVAL_S DURATION_S [COOKIE_FILE]: requests URL over one
keep-alive TLS connection every INTERVAL_S and prints latency percentiles plus
the slowest samples with their time offsets."""
import http.client, ssl, sys, time, statistics
from urllib.parse import urlparse

url, interval, dur = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
cookie = open(sys.argv[4]).read().strip() if len(sys.argv) > 4 else ""
u = urlparse(url)
ctx = ssl._create_unverified_context()
conn = None
lat = []
t0 = time.time()
while time.time() - t0 < dur:
    start = time.perf_counter()
    try:
        if conn is None:
            conn = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=60)
        conn.request("GET", u.path + ("?" + u.query if u.query else ""), headers={"Cookie": cookie} if cookie else {})
        r = conn.getresponse()
        r.read()
        ok = r.status
    except Exception as e:  # reconnect next time
        ok = repr(e)
        conn = None
    el = time.perf_counter() - start
    lat.append((time.time() - t0, el, ok))
    time.sleep(max(0, interval - el))
vals = sorted(x[1] for x in lat)
q = lambda p: vals[min(len(vals) - 1, int(p * len(vals)))] * 1000
print(f"{u.path}: n={len(vals)} p50={q(0.5):.1f}ms p90={q(0.9):.1f}ms p99={q(0.99):.1f}ms max={vals[-1]*1000:.1f}ms")
slow = sorted(lat, key=lambda x: -x[1])[:8]
print("  slowest:", " ".join(f"t={t:.0f}s:{e*1000:.0f}ms" for t, e, _ in sorted(slow)))
bad = [x for x in lat if x[2] != 200]
if bad:
    print("  non-200:", bad[:5])
