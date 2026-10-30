//! The master's own machine: CPU, memory and disk for the panel. Sampled on
//! the 5 s tick from /proc; CPU is the busy share between two samples.
//! Elsewhere than Linux there is nothing to read and the panel shows dashes.

use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

#[derive(Clone, Default, Serialize)]
pub struct Stats {
    pub cpu_pct: f64,
    pub mem_total: i64,
    pub mem_used: i64,
    pub disk_total: i64,
    pub disk_used: i64,
    pub uptime_s: i64,
    /// Resident memory of the master process itself.
    pub rss: i64,
    /// keel.db with its WAL.
    pub db_bytes: i64,
}

struct State {
    /// (busy, total) jiffies at the last sample.
    cpu: Option<(u64, u64)>,
    stats: Option<Stats>,
}

static STATE: Mutex<State> = Mutex::new(State { cpu: None, stats: None });

/// The last sample, if any was taken.
pub fn current() -> Option<Stats> {
    STATE.lock().unwrap_or_else(|e| e.into_inner()).stats.clone()
}

pub fn sample(data: &Path) {
    let Some(mem) = std::fs::read_to_string("/proc/meminfo").ok() else { return };
    let kib = |key: &str| -> i64 {
        mem.lines()
            .find_map(|l| l.strip_prefix(key)?.trim().strip_suffix("kB")?.trim().parse::<i64>().ok())
            .unwrap_or(0)
            * 1024
    };
    let mem_total = kib("MemTotal:");
    let mem_used = (mem_total - kib("MemAvailable:")).max(0);
    let rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("VmRSS:")?.trim().strip_suffix("kB")?.trim().parse::<i64>().ok()))
        .unwrap_or(0)
        * 1024;
    let uptime_s = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0) as i64;
    let (disk_total, disk_used) = disk(data);
    let db_bytes = ["keel.db", "keel.db-wal"].iter().filter_map(|f| std::fs::metadata(data.join(f)).ok()).map(|m| m.len() as i64).sum();
    let cpu_now = cpu_jiffies();

    let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let cpu_pct = match (st.cpu, cpu_now) {
        (Some((b0, t0)), Some((b1, t1))) if t1 > t0 => (b1.saturating_sub(b0)) as f64 * 100.0 / (t1 - t0) as f64,
        _ => 0.0,
    };
    st.cpu = cpu_now;
    st.stats = Some(Stats { cpu_pct: (cpu_pct * 10.0).round() / 10.0, mem_total, mem_used, disk_total, disk_used, uptime_s, rss, db_bytes });
}

/// (busy, total) from the first line of /proc/stat; idle and iowait are not busy.
fn cpu_jiffies() -> Option<(u64, u64)> {
    let s = std::fs::read_to_string("/proc/stat").ok()?;
    let v: Vec<u64> = s.lines().next()?.strip_prefix("cpu ")?.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    // user nice system idle iowait irq softirq steal (guest is inside user).
    let total: u64 = v.iter().take(8).sum();
    let idle = v.get(3).copied().unwrap_or(0) + v.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(idle), total))
}

#[cfg(unix)]
fn disk(path: &Path) -> (i64, i64) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return (0, 0) };
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a valid C string and s a writable statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return (0, 0);
    }
    let block = s.f_frsize as i64;
    let total = s.f_blocks as i64 * block;
    (total, total - s.f_bfree as i64 * block)
}

#[cfg(not(unix))]
fn disk(_: &Path) -> (i64, i64) {
    (0, 0)
}
