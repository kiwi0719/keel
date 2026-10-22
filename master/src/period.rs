//! Calendar helpers without a date library: accounting periods that reset on
//! a fixed day of the month, in the panel's configured UTC offset.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = m as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(y: i64, m: u32) -> u32 {
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    (days_from_civil(ny, nm, 1) - days_from_civil(y, m, 1)) as u32
}

/// Local (year, month, day) of a unix time at the given UTC offset.
pub fn local_date(ts: i64, offset_min: i64) -> (i64, u32, u32) {
    civil_from_days((ts + offset_min * 60).div_euclid(86_400))
}

/// The reset date of the period containing `ts` for a period that starts on
/// `day` each month (clamped to the month's length, so 31 means "last day").
pub fn period_start(ts: i64, offset_min: i64, day: u32) -> (i64, u32, u32) {
    let day = day.clamp(1, 31);
    let (y, m, d) = local_date(ts, offset_min);
    let this = day.min(days_in_month(y, m));
    if d >= this {
        return (y, m, this);
    }
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    (py, pm, day.min(days_in_month(py, pm)))
}

/// Unix time when the period containing `ts` ends.
pub fn period_end(ts: i64, offset_min: i64, day: u32) -> i64 {
    let (y, m, _) = period_start(ts, offset_min, day);
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    let d = day.clamp(1, 31).min(days_in_month(ny, nm));
    days_from_civil(ny, nm, d) * 86_400 - offset_min * 60
}

/// Period label sent to nodes, e.g. "2026-10-21". `seq` > 0 marks a manual
/// reset inside the same period, so nodes start counting from zero again.
pub fn period_label(ts: i64, offset_min: i64, day: u32, seq: i64) -> String {
    let (y, m, d) = period_start(ts, offset_min, day);
    if seq > 0 {
        format!("{y:04}-{m:02}-{d:02}#{seq}")
    } else {
        format!("{y:04}-{m:02}-{d:02}")
    }
}

/// Calendar month label for per-node monthly traffic.
pub fn month_label(ts: i64, offset_min: i64) -> String {
    let (y, m, _) = local_date(ts, offset_min);
    format!("{y:04}-{m:02}")
}

/// "2027-03-01" -> unix time at the end of that local day; "" -> 0 (never).
pub fn parse_date_end(s: &str, offset_min: i64) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: u32 = it.next()?.parse().ok()?;
    let d: u32 = it.next()?.parse().ok()?;
    if it.next().is_some() || !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    Some((days_from_civil(y, m, d) + 1) * 86_400 - offset_min * 60)
}

/// Inverse of parse_date_end: the local date whose end is `ts`.
pub fn format_date_end(ts: i64, offset_min: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    let (y, m, d) = local_date(ts - 1, offset_min);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip() {
        for days in [-1000, 0, 1, 59, 365, 10_957, 20_000, 29_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn periods() {
        let jst = 9 * 60;
        // 2026-10-22 12:00 JST
        let ts = (days_from_civil(2026, 10, 22) * 86_400) + 3 * 3600;
        assert_eq!(period_label(ts, jst, 21, 0), "2026-10-21");
        assert_eq!(period_label(ts, jst, 23, 0), "2026-09-23");
        assert_eq!(period_label(ts, jst, 23, 2), "2026-09-23#2");
        // day 31 in February is the last day
        let feb = days_from_civil(2027, 2, 28) * 86_400 + 3600;
        assert_eq!(period_label(feb, 0, 31, 0), "2027-02-28");
        assert_eq!(period_label(feb - 7200, 0, 31, 0), "2027-01-31");
        assert_eq!(period_end(ts, jst, 21), days_from_civil(2026, 11, 21) * 86_400 - jst * 60);
    }

    #[test]
    fn dates() {
        let e = parse_date_end("2027-03-01", 480).unwrap();
        assert_eq!(format_date_end(e, 480), "2027-03-01");
        assert_eq!(parse_date_end("", 0), Some(0));
        assert_eq!(parse_date_end("2027-02-30", 0), None);
    }
}
