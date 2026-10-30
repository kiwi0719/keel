#!/usr/bin/env python3
"""mon.py PID INTERVAL_S DURATION_S [LABEL]: prints RSS (ps), cumulative CPU seconds (ps) and
cumulative disk bytes written/read (proc_pid_rusage) once per interval, then the deltas."""
import ctypes, subprocess, sys, time

class RU(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [(n, ctypes.c_uint64) for n in (
        "user", "system", "pkg_idle", "intr", "pageins", "wired", "resident", "footprint", "start", "exit",
        "cuser", "csystem", "cpkg", "cintr", "cpageins", "celapsed", "dread", "dwritten")]

lib = ctypes.CDLL("/usr/lib/libproc.dylib")
pid, interval, dur = int(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
label = sys.argv[4] if len(sys.argv) > 4 else ""

def sample():
    ru = RU()
    lib.proc_pid_rusage(pid, 2, ctypes.byref(ru))
    out = subprocess.run(["ps", "-o", "rss=,time=", "-p", str(pid)], capture_output=True, text=True).stdout.split()
    rss = int(out[0]); t = out[1]
    parts = t.split(":"); cpu = float(parts[-1]) + 60 * float(parts[-2]) + (3600 * float(parts[-3]) if len(parts) > 2 else 0)
    return rss, cpu, ru.dwritten, ru.dread, ru.footprint

t0 = time.time(); s0 = sample(); peak = s0[0]
while time.time() - t0 < dur:
    time.sleep(interval)
    s = sample(); peak = max(peak, s[0])
    print(f"{label} t={time.time()-t0:6.1f}s rss={s[0]/1024:7.1f}MB footprint={s[4]/1048576:7.1f}MB cpu={s[1]-s0[1]:7.2f}s written={(s[2]-s0[2])/1048576:8.1f}MB read={(s[3]-s0[3])/1048576:7.1f}MB", flush=True)
s = sample(); el = time.time() - t0
print(f"{label} SUMMARY elapsed={el:.1f}s cpu={s[1]-s0[1]:.2f}s ({100*(s[1]-s0[1])/el:.1f}% of one core) disk_written={(s[2]-s0[2])/1048576:.1f}MB ({(s[2]-s0[2])/1048576/el:.2f} MB/s) footprint_end={s[4]/1048576:.1f}MB rss_end={s[0]/1024:.1f}MB rss_peak={peak/1024:.1f}MB", flush=True)
