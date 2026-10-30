#!/usr/bin/env python3
"""Emulates the admin panel's poller: setInterval(refresh, 2000) where refresh
is fetch('/api/state') with no in-flight guard. A browser allows at most 6
connections per host over HTTP/1.1, so at most 6 requests run at once and the
rest queue (modelled with a semaphore).

panel_poll.py URL COOKIE_FILE DURATION_S [TABS]
"""
import http.client, ssl, sys, threading, time
from urllib.parse import urlparse

url, cookie, dur = sys.argv[1], open(sys.argv[2]).read().strip(), float(sys.argv[3])
tabs = int(sys.argv[4]) if len(sys.argv) > 4 else 1
u = urlparse(url)
ctx = ssl._create_unverified_context()
slots = threading.Semaphore(6 * tabs)  # per-host connection limit (per browser profile it is 6 in total; tabs>1 = several browsers)
lock = threading.Lock()
inflight = 0
peak = 0
done = []


def one(t_fire):
    global inflight, peak
    with lock:
        inflight += 1
        peak = max(peak, inflight)
    with slots:
        t_start = time.time()
        try:
            c = http.client.HTTPSConnection(u.hostname, u.port, context=ctx, timeout=300)
            c.request("GET", u.path, headers={"Cookie": cookie})
            r = c.getresponse()
            r.read()
            c.close()
            st = r.status
        except Exception as e:
            st = repr(e)
    with lock:
        inflight -= 1
        done.append((t_fire, time.time() - t0 - t_fire, time.time() - t_start, st))


t0 = time.time()
threads = []
n = 0
while time.time() - t0 < dur:
    for _ in range(tabs):
        th = threading.Thread(target=one, args=(time.time() - t0,), daemon=True)
        th.start()
        threads.append(th)
    n += 1
    with lock:
        cur = inflight
    print(f"t={time.time()-t0:5.1f}s fired={n*tabs} completed={len(done)} in_flight={cur}", flush=True)
    time.sleep(2)
for th in threads:
    th.join(timeout=120)
lat = sorted(d[1] for d in done)
print(f"SUMMARY fired={n*tabs} completed={len(done)} peak_in_flight={peak} latency p50={lat[len(lat)//2]:.2f}s max={lat[-1]:.2f}s" if lat else "no completions")
