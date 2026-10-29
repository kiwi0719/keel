# keel-master perf audit — final report

SubagentHandback was refused three times ("session is not in auto mode"), so this file is the deliverable.

## Remaining steps (blocked by plan mode)
- Stop the one process still running: `kill 57438`. It is `$SCR/snap1/target/release/keel-master -data $SCR/small -listen 127.0.0.1:18443`. Every other process I started has exited. No load tests are running.
- Optionally delete `$SCR` (see Commands for the path).
- No repo files were edited.

## Which code was measured, and the line numbers
**Measurements: snapshot `snap1`.** The working tree was copied at about 03:01 on 2026-10-30, before commit d36c59a (03:27), into `$SCR/snap1`. All numbers come from the release build of that copy (sha1 a510892a…). The one exception is the small-dataset HTTP table, which came from the 02:49 repo build; its perf-relevant code is the same.

**Line numbers: current HEAD df07256.** `master/` is clean against HEAD.
- `ws.rs` and `util.rs` are byte-identical to the snapshot.
- These hot paths are unchanged: `World::used`, the `sync` loop, `store_usage`, `load_world`, `state_value`, and the subscription path.
- New on the hot paths in HEAD:
  - per-entry credentials: `User::credentials_for`, 2 SHA-256 per user per entry
  - `master_spki` in node configs
  - the `panel_cert` status in `/api/state`
  - the `spki_ready` UPDATE in `on_applied`

**Test conditions.**
- Apple M4, 10 cores, loopback only, TLS 1.2. A VPS core is roughly 1.5–3× slower.
- Another session's test runs added 20–50% run-to-run noise.

**Datasets** (every user on every entry, the panel default; 90% have a quota; 12 periods of history):

| Dataset | Nodes | Users | Usage rows (table / loaded by `load_world`) |
|---|---|---|---|
| small | 10 entries + 10 exits | 200 | 25.2K / 6.9K |
| medium | 10 + 10 | 1000 | 121K / 32.8K |
| large | 25 + 25 | 2000 | 607K / 164K |

## Findings

### 1. HIGH — `World::used` scans every loaded usage row, once per user
**Where.** `db.rs:516-522`. Callers:
- `nodecfg.rs:278`: `used_base` for every quota user in every entry config
- `nodecfg.rs:60-62` (`user_used`), which `api.rs:474` calls for every user in `/api/state`, and `sub.rs:502`

The same pattern is in `nodecfg.rs:68-75` (`exit_used`, called at `api.rs:464`) and `nodecfg.rs:312-317`.

**Cost.** One entry config is O(U²·E), one sync O(U²·E²), one `/api/state` O(U²·E).

**Measured.**
- `used` plus `memcmp` is about 95% of `/api/state` CPU and about 97% of sync CPU.
- `/api/state`: 7–23 ms on small, 120 ms on medium, 1.75–2.0 s (740 KB) on large.
- One large entry config takes about 1.5 s. `PATCH /api/users/2` took 0.18 s with no nodes online and 3.1–3.4 s with 2 entries online.

**Fix.** Aggregate once per World into `HashMap<(name, period), total>`. Then `used = total − own[skip]` is O(1). Do the same per (exit, period).

**Must preserve:** H4 and M1.
- Sum in Rust with saturating adds and skip bad rows. No SQL `up+down`: an overflowing sum turns into REAL and breaks `load_world`.
- Totals must only include counters each node is allowed to write.

### 2. HIGH — `App::sync` rebuilds every connected node's config inline, holding the DB and live mutexes
**Where.** `app.rs:66-111`; the DB lock is held from line 67, the live lock from line 79. It runs:
- on every connect (`ws.rs:124`)
- every 30 s (`main.rs:550`)
- before the response of every edit (`api.rs:656, 712, 737, 766, 874, 900, 915, 926, 993, 1008, 1023, 1040, 1046, 1155`)

**What it does per node.** Each sync builds the config and serializes it three times (`shape()` clones it, and `json!` copies it again). Each pushed node then gets its own autocommit UPDATE. A connect storm is O(N²) builds.

**Measured, connect storms.**

| Dataset | Result |
|---|---|
| small | First config median 0.13 s |
| medium | First config median 3.9 s, max 11.7 s. `/api/session` stalled up to 8.3 s, `/app.js` up to 4.4 s |
| large | 5 of 50 nodes got a config in 195 s; 49 dropped on ping timeouts. HTTP got no answer for the whole run. CPU stayed at 100% for more than 3.5 min after the clients left. SIGTERM was ignored for over 20 s |

On medium in steady state, each 30 s sync stalls the server for 0.7–1 s.

A reconnect feedback loop with real nodes (ping every 30 s, 15 s timeout, `cmd/keel-node/master.go:32,264`) is inferred, not tested.

**Overlap.** Security L7 is marked fixed, but only the Cloudflare part was changed. The full rebuild on every hello remains.

**Fix.**
1. Use one coalescing pusher task. On connect, build only that node.
2. Load under the lock, then build in `spawn_blocking` with no locks held.
3. Serialize once.
4. Batch the `config_rev` UPDATEs.

**Must preserve:**
- **M3:** the token re-check under the DB lock before registering a connection (`ws.rs:92-97`), `kick` ending the serve task, and dropping reports from non-current connections.
- **M5:** the queue of 16 and the 30 s write timeout.
- The db→live lock order.
- Prompt pushes after revocations: user disable or delete, sub rotation (L16), and per-entry credentials (L17). Coalescing may delay these by at most one run, never drop them.
- **H7:** the Cloudflare token stays out of configs.

### 3. HIGH, at every scale — `store_usage` commits once per row and rewrites every counter every 5 s
**Where.** `db.rs:646-655`, called from `app.rs:154`. The upsert always sets `updated`, and nodes report every user every 5 s even with no traffic.

**Measured with `wal_bench.py`:**

| Rows per report | One commit per row | One transaction | Skip unchanged rows |
|---|---|---|---|
| 2000 | 2000 WAL frames, 7.8 MB, 13–38 ms | 46 frames, 0.18 MB, about 2 ms | 0 frames when idle |
| 200 | 200 frames | 22 frames | — |

**Measured on the live server.** small 1.54 MB/s (about 130 GB/day); medium 7.95 MB/s (about 690 GB/day). Independent of traffic.

**Fix.** One transaction per report, plus `WHERE excluded.up>usage.up OR excluded.down>usage.down` on the upsert.

**Must preserve:**
- **H4/M1:** allowed counters only, clamped to [0, `MAX_COUNTER`].
- **L5:** counters only grow within a period.
- The 70-day `load_world` window. This holds, because `updated` advances on every growth.
- **M4:** bounded row creation.

### 4. MEDIUM-HIGH — `/api/state` is rebuilt per poll inline, holding the live lock; the panel has no in-flight guard
**Where.**
- `api.rs:303-304`
- `api.rs:363-512`; the live lock is taken at 375
- `api.rs:487`, which is O(U·N)
- `app.js:121-131` and `1240`

`on_report` takes DB then live (`app.rs:144`, `158`), so a slow build also blocks reports.

**Measured.**
- One tab on large uses 86% of a core.
- Two tabs: 27 requests in flight, p50 24 s, max 44 s.
- 4 concurrent clients get the same throughput as 1.
- One `/api/public` rebuild costs a full state build: 1.8 s on large, 130–146 ms on medium.

**Fix.**
- Fix finding 1 first.
- Build in `spawn_blocking` and copy out the live fields.
- Precompute per-counter `conns` totals.
- Share a 1 s snapshot.
- In the JS, skip ticks while a request is in flight and back off.
- Add an ETag or split static data from live data.

**Must preserve:**
- **L12:** `no-store`.
- **M9:** login and the `x-keel` check, so the snapshot is served only after the login check.
- **M6:** `/api/public` built at most once per interval, off the async workers.
- **L13:** the public page stays opt-in and its field whitelist stays.

### 5. MEDIUM — each subscription request loads the whole world under the DB mutex
**Where.** `sub.rs:473-480`; `base_url` locks again at line 500; line 502 does a full scan.

**Measured:**

| Dataset | Latency | Throughput, 1 client | Throughput, 8 clients |
|---|---|---|---|
| small | 2.5–3.3 ms | — | — |
| medium | 12–13 ms | — | — |
| large | 66–99 ms | 10–15 rps | 6.6 rps (max latency 3.9 s, RSS 44→188 MB) |

**Fix.** Query only that user's data, in `spawn_blocking`.

**Must preserve:**
- **H3:** list only entries clients can verify or pin; ACME entries only after the cert is reported issued.
- **L16/L17:** `credentials_for`.
- Unknown token returns 404.
- **L12:** `no-store`.

### 6. MEDIUM — one std `Mutex<Connection>` taken on async workers everywhere
**Where.** `app.rs:31-48`. Callers include:
- `logged_in` on every authenticated request (`api.rs:89-94`)
- `ws.rs:61`, `92-97` and `141`
- `on_report` (`app.rs:142-197`)

**Measured.** `/app.js` max 4.4 s on medium. With 1 tokio worker, max 12.8 s.

**Fix.** Use `spawn_blocking` or a DB thread, hold the lock only around SQL, and add a read-only second connection.

**Must preserve:**
- **M3:** registration and rotation/deletion under the same lock.
- **L8:** argon2 off-thread.
- The DB, `-wal` and `-shm` files at mode 0600.

### 7. MEDIUM on large, LOW on small — usage-only changes re-push the full config every 60 s
**Where.** `app.rs:22`, `92-96`; `nodecfg.rs:342-353`.

**Measured.** A full config per entry every minute: 56 KB on small, 267 KB on medium, 532 KB on large.

**Fix.** A small `usage` message. This needs a protocol change.

**Must preserve:** master-computed `used_base` from allowed counters, a monotonic `rev`, and quota enforcement (L5).

### 8. LOW-MEDIUM — redundant work in the report path
- `ws.rs:137` and `147` parse the report, then clone it.
- `node_counters` (`db.rs:635-642`) scans `user_entries`, because the primary key is `(user_id, node_id)` (`db.rs:95`).
- `tz` is read on every report (`app.rs:157`).
- `conns` is rebuilt on every report (`app.rs:161`).

**Fix.** Parse once; add an index on `user_entries(node_id)`; cache the allowed counter set.

**Must preserve:**
- **L4:** a bad section must not drop the usage counters.
- **M1:** the cache must be invalidated whenever `user_entries` or exits change.
- **M3:** the current-connection check.
- **M4:** the probe caps.
- The 4 MiB message cap.

### 9. LOW — `load_world` full-scans `usage`, which keeps 400 days
**Where.** `db.rs:578`, `675`. 607K rows scanned to return 164K, 18 ms.

**Fix.** An index on `usage(updated)`.

**Must preserve:** H4's skip-bad-rows.

### 10. LOW — whole-world loads for a single item
**Where.**
- `api.rs:1017`
- `main.rs:257`
- `dns.rs:60`
- `dns.rs:191`

**Must preserve:**
- `node_ports`: node-token auth and the 1 s delay on a bad token.
- `acme_challenge`: the domain comes only from the node's own settings (H7).

### 11. LOW — memory versus the README's "~7 MB" (macOS)
- Idle: 5–6 MB.
- small, 2 nodes, panel polling, no login: 23–29 MB RSS, 19–25 MB footprint.
- A login runs argon2 with m=19 MiB; RSS went to 45 MB transiently.
- large: 151–188 MB transient.
- `/dl` caches every binary for the life of the process (`main.rs:267-285`). Read from code, not measured.

**Fix.** Stream `/dl` from disk.

**Must preserve H1:** no full copy per connection, keep the connection caps and timeouts, and keep the filename whitelist.

### 12. LOW — the timer bursts after a slow tick
**Where.** `main.rs:543-556`, default `MissedTickBehavior::Burst`.

**Fix.** `Delay`.

### 13. LOW-MEDIUM, client side — the panel re-renders everything on every poll
**Where.**
- `app.js:125-130`: the change check never matches because of `now`.
- `app.js:165-186`: full innerHTML.
- `app.js:149-161`: two renders per action.
- `app.js:503-504`: O(U·E·N).

**Measured.**
- 10 polls gave 10 full re-renders.
- Users tab: 18,020 elements, about 73 ms with layout.
- Lines tab: 16 ms. Probe tab: 5 ms.
- `JSON.stringify` 0.6 ms, parse 0.9 ms.
- Heap flat.

**Fix.** Exclude volatile fields from the comparison, patch only the active tab, and use a node `Map`.

**Must preserve:** `esc()` on every interpolation (or `textContent`), `x-keel` on writes (M9), and `credentials: same-origin`.

### 14. INFO — small allocation costs
- `util.rs:12-13`: `hex()` calls `format!` once per byte.
- `sub.rs:82` and `95` call `credentials_for` twice per entry.

**Must preserve:** byte-identical outputs, so session keys, config hashes and derived credentials don't change.

### 15. INFO — Cloudflare client (code only)
**Where.** `dns.rs:143-150` creates a root store and a TLS connection per call.

**Fix.** Build the TLS config once and reuse the connection.

**Must preserve:** webpki verification, the 20 s timeout, the token only ever sent to api.cloudflare.com, and H7.

## Checked and fine
- **Bounded buffers.** Speed 36 points, probes 120 × 8, certs 8 (`live.rs:12-16`, `186-193`, `217`).
- **WebSocket queue.** Bounded at 16, 30 s write timeout, 4 MiB message cap.
- **Config pushes.** Nothing is sent when the hash is unchanged.
- **argon2.** Runs in `spawn_blocking`, at most 2 at a time.
- **Indexes.** `/api/public` is cached; token lookups use indexes.
- **Static assets.** Compiled in; the CSS is cheap.
- **Panel basics.** Listeners delegated once, polling stops while hidden, the drawer is not re-rendered, charts are cheap.
- **Subscription rendering.** Cheap in itself.
- **SQLite settings.** WAL with synchronous=NORMAL is fine.

## Commands
```sh
SCR=/private/tmp/claude-501/-Users-kiwi-Desktop-keel/f8d97281-40ad-485b-931d-05a586702401/scratchpad/master-perf
cd $SCR/snap1/master && cargo build --release --locked --target-dir $SCR/snap1/target
cargo build --release --locked --target-dir $SCR/snap1/target-prof --config 'profile.release.strip=false' --config 'profile.release.debug="line-tables-only"'
BIN=$SCR/snap1/target/release/keel-master
$BIN -data $SCR/large -listen 127.0.0.1:18444 & sleep 2; kill %1
python3 -I $SCR/seed.py $SCR/large/keel.db 25 25 2000 12        # small: 10 10 200 12, medium: 10 10 1000 12
sqlite3 $SCR/large/keel.db "INSERT INTO settings(key,value) VALUES('public_page','1') ON CONFLICT(key) DO UPDATE SET value='1'"
$BIN -data $SCR/large -listen 127.0.0.1:18444 > $SCR/logs/large.log 2>&1 &
$SCR/login.sh $SCR/large 18444
$SCR/bench_http.sh 18444 $SCR/large <PID> 10    # /usr/sbin/ab -q -f TLS1.2 -n N -c C -k [-H "Cookie: ..."] URL
$SCR/patch_lat.sh 18444 3
python3 -I $SCR/mon.py <PID> 5 205 label
python3 -I $SCR/probe_lat.py https://127.0.0.1:18444/api/session 0.5 200 $SCR/cookie-18444.txt
python3 -I $SCR/sim.py --port 18444 --db $SCR/large/keel.db --duration 195 --traffic 0.2 --stats $SCR/logs/sim-large.json
python3 -I $SCR/panel_poll.py https://127.0.0.1:18444/api/state $SCR/cookie-18444.txt 60 2
TOKIO_WORKER_THREADS=1 $BIN -data $SCR/medium -listen 127.0.0.1:18445
python3 -I $SCR/wal_bench.py $SCR/large/keel.db 1 20
sample <PID> 7 -mayDie -file $SCR/logs/sample-state.txt   # with the target-prof binary
```
- The panel measurements used `performance.now()` around `render()` against a `-no-tls` master on 18446, with a session row inserted directly into the DB.
- Logs are in `$SCR/logs/`.

## Not verified
Linux RSS, physical device writes, real keel-node binaries (I used a Python simulator), VPS CPU speed, Cloudflare, phone rendering, `/dl` RSS, node-side push cost, and gzip.
