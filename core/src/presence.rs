//! Presence of an address across the run history: which finished scanner runs covered it
//! (target list minus excluded addresses and failed batches — `history::Coverage`) and
//! whether it answered in each. Two uses:
//!
//! - findings: something last observed in run R is no longer current when a LATER run
//!   covered the same address (and port) without observing it (`Presence::after`);
//! - time of day: hosts whose presence depends on the hour (`time_of_day_pattern`), e.g.
//!   workstations or lab equipment visible only during working hours.
//!
//! Imported runs never count: they do not say what was absent, nor when it was measured.

use crate::{history::Coverage, input::Target, pipeline::RunStats};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

/// A finished scanner run as a measurement of presence.
struct RunCover {
    id: Uuid,
    at: DateTime<Utc>,
    /// Hour of day of the run's start, Europe/Warsaw (the dashboard's time zone, like the
    /// availability heatmap). The run's start stands for the whole run: lab and daily runs
    /// last minutes, and a host's absence has no timestamp of its own.
    hour: u8,
    coverage: Coverage,
    /// `config_snapshot.ports`: explicit list, or a top-N/full preset.
    ports: Option<String>,
}

/// One measurement of an address: the hour (Europe/Warsaw) and whether it answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    pub hour: u8,
    pub present: bool,
}

/// What runs after the latest observation of a finding say about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Later {
    /// No later run covered the address (and port): the observation is current.
    NotRescanned,
    /// Later runs covered it, but the host did not answer in any of them (`unstable` row or
    /// no row at all): not seen, not confirmed gone either.
    HostSilent,
    /// A later run saw the host (or marked it inactive) without this finding: it is gone.
    Gone,
}

pub struct Presence {
    /// Oldest first.
    runs: Vec<RunCover>,
    /// (run, address) → host state recorded by that run.
    states: HashMap<(Uuid, String), String>,
}

/// The DNS name of a URL (`None` for an IP literal or an unparsable URL).
pub fn url_vhost(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if authority.starts_with('[') {
        return None; // IPv6 literal
    }
    let host = authority.split(':').next()?;
    (!host.is_empty() && host.parse::<std::net::IpAddr>().is_err()).then_some(host)
}

/// Is `port` among the ports a run scanned? Presets that cannot be expanded here count as
/// covering (a top-N list is checked when nmap's ranking is available).
fn ports_cover(spec: Option<&str>, port: Option<u16>) -> bool {
    let (Some(spec), Some(port)) = (spec.map(str::trim).filter(|s| !s.is_empty()), port) else {
        return true;
    };
    match spec {
        "full" => true,
        "100" => crate::v1_scans::in_top_ports(100, port).unwrap_or(true),
        "1000" => crate::v1_scans::in_top_ports(1000, port).unwrap_or(true),
        list => list.split(',').any(|part| {
            let (a, b) = part.split_once('-').unwrap_or((part, part));
            match (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                (Ok(a), Ok(b)) => (a..=b).contains(&port),
                _ => false,
            }
        }),
    }
}

impl Presence {
    pub async fn load(db: &PgPool) -> sqlx::Result<Self> {
        type RunRow = (Uuid, DateTime<Utc>, i32, sqlx::types::Json<Vec<Target>>, sqlx::types::Json<RunStats>, Option<String>);
        let rows: Vec<RunRow> = sqlx::query_as(
            "SELECT id, started_at, extract(hour FROM started_at AT TIME ZONE 'Europe/Warsaw')::int,
                    target_snapshot, stats, config_snapshot->>'ports'
             FROM scan_runs
             WHERE status IN ('done', 'partial') AND source = 'scanner' AND target_snapshot IS NOT NULL
             ORDER BY started_at",
        )
        .fetch_all(db)
        .await?;
        let runs = rows
            .into_iter()
            .map(|(id, at, hour, targets, stats, ports)| RunCover {
                id,
                at,
                hour: hour.clamp(0, 23) as u8,
                coverage: Coverage::new(&targets.0, &stats.0.failed_ranges),
                ports,
            })
            .collect();
        let states = sqlx::query_as::<_, (Uuid, String, String)>(
            "SELECT h.run_id, host(h.address), h.state::text FROM hosts h JOIN scan_runs r ON r.id = h.run_id
             WHERE r.status IN ('done', 'partial') AND r.source = 'scanner'",
        )
        .fetch_all(db)
        .await?
        .into_iter()
        .map(|(run, ip, state)| ((run, ip), state))
        .collect();
        Ok(Self { runs, states })
    }

    /// Every finished scanner run that covered this address, oldest first.
    pub fn samples(&self, ip: &str, hostname: Option<&str>) -> Vec<Sample> {
        self.runs
            .iter()
            .filter(|r| r.coverage.covers(ip, hostname))
            .map(|r| Sample { hour: r.hour, present: self.states.get(&(r.id, ip.to_string())).is_some_and(|s| s == "active") })
            .collect()
    }

    /// What runs started after `seen_at` (the run of the latest observation) say about
    /// something on this address and port. `vhost`: the DNS name the observation was made
    /// through (`http://blog.example/`) — only runs that targeted that name probed it, so a
    /// scan of the bare address does not make it gone.
    pub fn after(&self, ip: &str, hostname: Option<&str>, port: Option<u16>, vhost: Option<&str>, seen_at: DateTime<Utc>) -> Later {
        let mut later = Later::NotRescanned;
        for r in self.runs.iter().filter(|r| r.at > seen_at) {
            if !r.coverage.covers(ip, hostname)
                || !ports_cover(r.ports.as_deref(), port)
                || vhost.is_some_and(|name| !r.coverage.has_domain(name))
            {
                continue;
            }
            match self.states.get(&(r.id, ip.to_string())).map(String::as_str) {
                Some("active" | "inactive") => return Later::Gone,
                _ => later = Later::HostSilent,
            }
        }
        later
    }
}

// ---------- time of day ----------

/// A host must have answered in at least this many runs inside the hours, and been checked
/// (and silent) in at least this many runs outside them — one lucky or unlucky measurement
/// never makes a pattern.
pub const MIN_RUNS_EACH_SIDE: usize = 2;
/// Inside the hours a host may miss a probe now and then, but must answer in ≥ 75% of runs.
pub const MIN_INSIDE_RATE: f64 = 0.75;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimePattern {
    /// Hours (Europe/Warsaw) when the host answers: from `start_hour` up to `end_hour`
    /// (exclusive; `end_hour <= start_hour` means the window crosses midnight).
    pub start_hour: u8,
    pub end_hour: u8,
    pub inside_responded: usize,
    pub inside_total: usize,
    pub outside_responded: usize,
    pub outside_total: usize,
    /// Short label for a chip: "Widoczny tylko 08–18" / "Niewidoczny 18–08".
    pub label: String,
    /// Why it is flagged, with the counts behind it.
    pub reason: String,
}

/// "08" as the start of a span; as its end, midnight reads "24".
fn from_h(h: u8) -> String {
    format!("{h:02}")
}

fn to_h(h: u8) -> String {
    format!("{:02}", if h == 0 { 24 } else { h })
}

fn in_window(hour: u8, start: u8, end: u8) -> bool {
    if start < end { (start..end).contains(&hour) } else { hour >= start || hour < end }
}

/// Explainable time-of-day rule over `samples` (oldest first). The window is the shortest
/// span of hours (on the 24-hour circle) that holds every run in which the host answered —
/// i.e. the complement of the longest stretch of hours without an answer. It is a pattern when:
/// - the host answered in ≥ `MIN_RUNS_EACH_SIDE` runs inside it, in ≥ `MIN_INSIDE_RATE` of them,
/// - ≥ `MIN_RUNS_EACH_SIDE` runs outside it found the host silent (by construction it never
///   answered there),
/// - and it repeated: the host was silent outside the hours AFTER answering inside them, and
///   answered inside them AFTER being silent outside. A host that simply came up (or went
///   down) once during the history is not a time-of-day pattern.
///
/// Hour of day only; weekdays are not told apart.
pub fn time_of_day_pattern(samples: &[Sample]) -> Option<TimePattern> {
    let mut hours: Vec<u8> = samples.iter().filter(|s| s.present).map(|s| s.hour % 24).collect();
    hours.sort_unstable();
    hours.dedup();
    let (&first, &last) = (hours.first()?, hours.last()?);
    // Longest run of hours without an answer between consecutive answering hours (circular).
    let mut best: (u8, u8, u8) = ((first + 24 - last - 1) % 24, last, first); // (gap, before, after)
    for w in hours.windows(2) {
        let gap = w[1] - w[0] - 1;
        if gap > best.0 {
            best = (gap, w[0], w[1]);
        }
    }
    let (gap, before, after) = best;
    if gap == 0 {
        return None; // answers around the clock
    }
    let (start, end) = (after, (before + 1) % 24);
    let (inside, outside): (Vec<&Sample>, Vec<&Sample>) = samples.iter().partition(|s| in_window(s.hour % 24, start, end));
    let inside_responded = inside.iter().filter(|s| s.present).count();
    let outside_responded = outside.iter().filter(|s| s.present).count();
    if outside.len() < MIN_RUNS_EACH_SIDE
        || inside_responded < MIN_RUNS_EACH_SIDE
        || (inside_responded as f64) < MIN_INSIDE_RATE * inside.len() as f64
        || outside_responded > 0
    {
        return None;
    }
    // Position (in time) of the first/last answer inside and of the first/last silence outside.
    let answered: Vec<usize> = samples.iter().enumerate().filter(|(_, s)| s.present).map(|(i, _)| i).collect();
    let silent_outside: Vec<usize> = samples
        .iter()
        .enumerate()
        .filter(|(_, s)| !s.present && !in_window(s.hour % 24, start, end))
        .map(|(i, _)| i)
        .collect();
    let repeated = answered.first() < silent_outside.last() && silent_outside.first() < answered.last();
    if !repeated {
        return None;
    }
    let window_len = (end + 24 - start - 1) % 24 + 1;
    let (label, reason) = if window_len <= 12 {
        (
            format!("Widoczny tylko {}–{}", from_h(start), to_h(end)),
            format!(
                "Odpowiada tylko w godzinach {}–{} (Europe/Warsaw): w {inside_responded} z {} skanów w tych godzinach, w 0 z {} poza nimi.",
                from_h(start),
                to_h(end),
                inside.len(),
                outside.len()
            ),
        )
    } else {
        (
            format!("Niewidoczny {}–{}", from_h(end), to_h(start)),
            format!(
                "Nie odpowiada w godzinach {}–{} (Europe/Warsaw): w 0 z {} skanów w tych godzinach, w pozostałych w {inside_responded} z {}.",
                from_h(end),
                to_h(start),
                outside.len(),
                inside.len()
            ),
        )
    };
    Some(TimePattern {
        start_hour: start,
        end_hour: end,
        inside_responded,
        inside_total: inside.len(),
        outside_responded,
        outside_total: outside.len(),
        label,
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(list: &[(u8, bool)]) -> Vec<Sample> {
        list.iter().map(|&(hour, present)| Sample { hour, present }).collect()
    }

    #[test]
    fn office_hours_host() {
        let p = time_of_day_pattern(&s(&[(8, true), (12, true), (17, true), (21, false), (2, false), (10, true)])).unwrap();
        assert_eq!((p.start_hour, p.end_hour), (8, 18));
        assert_eq!((p.inside_responded, p.inside_total, p.outside_responded, p.outside_total), (4, 4, 0, 2));
        assert_eq!(p.label, "Widoczny tylko 08–18");
        assert!(p.reason.contains("08–18") && p.reason.contains("w 4 z 4") && p.reason.contains("w 0 z 2"), "{}", p.reason);
    }

    #[test]
    fn a_host_that_came_up_once_is_not_a_pattern() {
        // Silent at 4, 5 and 6, then up from 7 on (one day of history): no repetition.
        assert_eq!(time_of_day_pattern(&s(&[(4, false), (5, false), (6, false), (7, true), (8, true), (9, true)])), None);
        // Up in the morning, then down for good.
        assert_eq!(time_of_day_pattern(&s(&[(8, true), (9, true), (10, false), (11, false)])), None);
        // The same hours over two days: up 8–10, silent at night, up again.
        let p = time_of_day_pattern(&s(&[(8, true), (9, true), (22, false), (3, false), (8, true), (9, true)])).unwrap();
        assert_eq!(p.label, "Widoczny tylko 08–10");
    }

    #[test]
    fn needs_two_runs_on_each_side() {
        // Only one run outside the hours.
        assert_eq!(time_of_day_pattern(&s(&[(9, true), (11, true), (15, true), (22, false)])), None);
        // Only one answer inside.
        assert_eq!(time_of_day_pattern(&s(&[(9, true), (22, false), (23, false), (3, false)])), None);
        // Never answered, or always answered.
        assert_eq!(time_of_day_pattern(&s(&[(9, false), (22, false), (23, false)])), None);
        assert_eq!(time_of_day_pattern(&s(&[(9, true), (22, true), (3, true)])), None);
    }

    #[test]
    fn an_answer_outside_breaks_the_pattern() {
        // Answers at 9, 14 and once at 23: the shortest span holding every answer is 09–24,
        // and the silent runs at 2 and 5 are the only ones left outside (2 runs) — still a
        // pattern, but a wider one; with an answer at 3 as well, nothing is left.
        let p = time_of_day_pattern(&s(&[(2, false), (9, true), (14, true), (5, false), (23, true)])).unwrap();
        assert_eq!((p.start_hour, p.end_hour), (9, 0));
        assert_eq!(p.label, "Niewidoczny 00–09");
        assert_eq!(time_of_day_pattern(&s(&[(2, false), (9, true), (14, true), (5, false), (23, true), (3, true)])), None);
    }

    #[test]
    fn too_many_misses_inside() {
        // Inside 08–18 it answered in 2 of 4 runs: < 75%, no clean pattern.
        assert_eq!(time_of_day_pattern(&s(&[(8, true), (17, true), (12, false), (13, false), (22, false), (1, false)])), None);
        // 3 of 4 is enough.
        assert!(time_of_day_pattern(&s(&[(22, false), (8, true), (17, true), (1, false), (12, true), (13, false)])).is_some());
    }

    #[test]
    fn night_window_crosses_midnight() {
        let p = time_of_day_pattern(&s(&[(10, false), (22, true), (23, true), (14, false), (3, true)])).unwrap();
        assert_eq!((p.start_hour, p.end_hour), (22, 4));
        assert_eq!(p.label, "Widoczny tylko 22–04");
        assert!(in_window(0, 22, 4) && !in_window(4, 22, 4));
    }

    #[test]
    fn mostly_up_host_with_a_quiet_period() {
        // Answers from 6 to 21, silent at night: reads as "not visible 22–06".
        let p = time_of_day_pattern(&s(&[(23, false), (6, true), (9, true), (2, false), (13, true), (21, true), (4, false)])).unwrap();
        assert_eq!((p.start_hour, p.end_hour), (6, 22));
        assert_eq!(p.label, "Niewidoczny 22–06");
        assert!(p.reason.starts_with("Nie odpowiada w godzinach 22–06"), "{}", p.reason);
    }

    #[test]
    fn vhost_of_a_url() {
        assert_eq!(url_vhost("http://blog.asi.test/wp-login.php"), Some("blog.asi.test"));
        assert_eq!(url_vhost("https://api.asi.test:8443"), Some("api.asi.test"));
        assert_eq!(url_vhost("http://172.30.0.12:80"), None);
        assert_eq!(url_vhost("http://[fd00::1]:80/"), None);
    }

    #[test]
    fn port_lists() {
        assert!(ports_cover(Some("22,80,8000-8009"), Some(8005)));
        assert!(!ports_cover(Some("22,80,8000-8009"), Some(443)));
        assert!(ports_cover(Some("full"), Some(1)));
        assert!(ports_cover(None, Some(443)));
        assert!(ports_cover(Some("22"), None));
    }
}
