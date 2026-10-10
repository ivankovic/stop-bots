/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! "Update everything": every downloadable list this host uses, as a plan
//! of fetch-then-store pairs.
//!
//! Lifted out of `batch::update_lists` when the web console needed the same
//! button, for the reason `scanblock`, `accessstats` and `dynamic` were
//! lifted out before: two front-ends running their own version of "update
//! everything" is two front-ends that will eventually update different
//! things, and the one that updates less is the one that quietly stops
//! protecting anybody.
//!
//! The split is not a style choice. `Db` is not `Sync`, so it cannot be
//! held across an `.await`; the web console reaches its database through
//! `spawn_blocking`, which needs `Send + 'static`. `batch::update_lists`
//! was an `async fn` holding `&Db` across every fetch, which works exactly
//! once — in `batch`, on a current-thread runtime — and nowhere else.
//! [`fetch`] touches no database and [`store`] touches no network, so
//! either front-end can drive them in whatever order its runtime allows.

use anyhow::{Context, Result};

use crate::db::Db;
use crate::ipranges::reputation::ReputationSourceKind;
use crate::ipranges::IpRangeSourceKind;
use crate::{botlist, ipranges};

/// One downloadable list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A bot list: user-agent patterns.
    BotList(botlist::SourceKind),
    /// A crawler's published IP ranges — Googlebot, Bingbot, GPTBot.
    CrawlerRanges(IpRangeSourceKind),
    /// A reputation or cloud-provider feed. Only enabled ones are planned.
    Reputation(ReputationSourceKind),
    /// A selected country's IPdeny zone file, by two-letter code.
    Country(String),
}

impl Source {
    /// How this source is named in a report, stable across runs so two
    /// reports can be diffed.
    pub fn label(&self) -> String {
        match self {
            Source::BotList(kind) => format!("bot list {}", kind.id()),
            Source::CrawlerRanges(kind) => format!("crawler ranges {}", kind.id()),
            Source::Reputation(kind) => format!("feed {}", kind.id()),
            Source::Country(code) => format!("country {code}"),
        }
    }
}

/// Everything an "update everything" would fetch, in a deterministic order.
///
/// Bot lists, then crawler ranges, then the *enabled* reputation feeds,
/// then the *selected* countries. The last two are read from the database
/// rather than enumerated: a feed nobody turned on and a country nobody
/// chose are not things this host uses, and fetching them would be six
/// pointless requests and a table full of ranges no rule references.
pub fn plan(db: &Db) -> Result<Vec<Source>> {
    let mut plan: Vec<Source> = botlist::SourceKind::ALL
        .into_iter()
        .map(Source::BotList)
        .chain(
            IpRangeSourceKind::ALL
                .into_iter()
                .map(Source::CrawlerRanges),
        )
        .collect();

    for source in db
        .list_reputation_sources()
        .context("could not read which feeds are enabled")?
        .into_iter()
        .filter(|s| s.enabled)
    {
        // A row whose id no longer maps to a known kind is skipped rather
        // than failing the plan: it can only come from a database written
        // by a version that had a feed this one dropped.
        if let Some(kind) = ReputationSourceKind::from_id(&source.id) {
            plan.push(Source::Reputation(kind));
        }
    }

    for code in db
        .list_selected_countries()
        .context("could not read which countries are selected")?
    {
        plan.push(Source::Country(code));
    }

    Ok(plan)
}

/// The network half: downloads `source`, touching no database.
pub async fn fetch(source: &Source) -> Result<String> {
    match source {
        Source::BotList(kind) => kind.fetch().await,
        Source::CrawlerRanges(kind) => kind.fetch().await,
        Source::Reputation(kind) => kind.fetch().await,
        Source::Country(code) => ipranges::fetch_country(code).await,
    }
}

/// The database half: parses `raw` and stores it, returning a one-line
/// summary of what landed.
pub fn store(db: &Db, source: &Source, raw: &str) -> Result<String> {
    match source {
        Source::BotList(kind) => {
            let parsed = kind.parse_counted(raw)?;
            let count = botlist::store(db, *kind, &parsed.bots)?;
            Ok(parsed.summary(count))
        }
        Source::CrawlerRanges(kind) => {
            let cidrs = kind.parse(raw)?;
            let count = ipranges::store(db, *kind, &cidrs)?;
            Ok(ranges_summary(count, &cidrs))
        }
        Source::Reputation(kind) => {
            let cidrs = kind.parse(raw)?;
            let count = ipranges::reputation::store(db, *kind, &cidrs)?;
            Ok(ranges_summary(count, &cidrs))
        }
        Source::Country(code) => {
            let count = ipranges::store_country(db, code, raw)?;
            Ok(ranges_summary(count, &ipranges::parse_zone_file(raw)))
        }
    }
}

/// "N range(s)", plus what storing `cidrs` dropped as too broad, if it
/// dropped anything — this summary is what `batch` prints to a cron log and
/// the console shows after "Update everything", so it is where a tampered
/// feed has to show up.
fn ranges_summary(count: usize, cidrs: &[String]) -> String {
    match ipranges::too_broad_note(cidrs) {
        Some(note) => format!("{count} range(s); {note}"),
        None => format!("{count} range(s)"),
    }
}

/// Whether every crawler-range source in `outcomes` succeeded.
///
/// The internal cron treats all three as the single `UpdateIpRanges` job,
/// so it may only be recorded as done when all three worked — otherwise a
/// front-end would skip re-fetching the one that failed until tomorrow.
pub fn crawler_ranges_all_succeeded(outcomes: &[(Source, Result<String, String>)]) -> bool {
    outcomes
        .iter()
        .filter(|(source, _)| matches!(source, Source::CrawlerRanges(_)))
        .all(|(_, outcome)| outcome.is_ok())
}

/// Records a finished "update everything" against the internal cron and
/// returns the one line to show for it: "Updated 7 list(s).", and what
/// failed.
///
/// Both jobs it covers are marked run: `UpdateEverything` always, so the
/// weekly job does not repeat what someone just did by hand, and
/// `UpdateIpRanges` only when every crawler source worked (see
/// [`crawler_ranges_all_succeeded`]). `by` says who, for the latter's
/// summary: "from the Dashboard", "by batch run".
pub fn record(db: &Db, outcomes: &[(Source, Result<String, String>)], by: &str) -> String {
    use crate::cron::{record_run, CronJob};
    if crawler_ranges_all_succeeded(outcomes) {
        record_run(db, CronJob::UpdateIpRanges, &format!("updated {by}"));
    }
    let failures: Vec<String> = outcomes
        .iter()
        .filter_map(|(source, outcome)| {
            outcome
                .as_ref()
                .err()
                .map(|err| format!("{}: {err}", source.label()))
        })
        .collect();
    let done = outcomes.len() - failures.len();
    let summary = if failures.is_empty() {
        format!("Updated {done} list(s).")
    } else {
        format!(
            "Updated {done} list(s). {} failed \u{2014} {}",
            failures.len(),
            failures.join("; ")
        )
    };
    record_run(db, CronJob::UpdateEverything, &summary);
    summary
}

// ---- one download at a time, across every stop-bots ----

/// How long a download may go without a sign of life before another
/// process may take over. Every holder renews after each source, and one
/// source is bounded by [`crate::fetch::TIMEOUT`] plus its connect
/// timeout — seventy seconds — so ten minutes only ever expires a holder
/// that died.
pub const LEASE_SECONDS: i64 = 10 * 60;

/// The right to download lists, recorded in the database so that the TUI,
/// the console and a `batch` from cron all see it.
///
/// "Update everything" and the internal cron's jobs used to fetch the same
/// feeds at once: the TUI kept its own interlock per job, and the console
/// had none at all between its button and its cron. Nothing corrupted
/// (every store replaces), but it was duplicate traffic to the same third
/// parties. A row rather than a lock file: every front-end already shares
/// the database, a row outlives nothing it should not (it expires), and a
/// process that dies holding it costs [`LEASE_SECONDS`] at most.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    holder: String,
}

/// What asking for the [`Lease`] got.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    Granted(Lease),
    /// Someone else is downloading, and last renewed at `since`.
    Busy {
        since: i64,
    },
}

impl Claim {
    /// Why nothing was downloaded, for a front-end to say.
    pub fn busy_message(since: i64) -> String {
        format!(
            "Another update is downloading the lists (last active {}); nothing was fetched twice.",
            crate::present::ago(since)
        )
    }
}

/// The stored lease: when it was last renewed, and by whom.
fn read_lease(db: &Db) -> Result<Option<(i64, String)>> {
    Ok(db
        .get_text_setting(crate::db::keys::REFRESH_LEASE)?
        .and_then(|value| {
            let (since, holder) = value.split_once(' ')?;
            Some((since.parse().ok()?, holder.to_string()))
        }))
}

/// Takes the lease as of `now`, unless someone else holds one they
/// renewed within [`LEASE_SECONDS`]. The read and the write are one
/// `BEGIN IMMEDIATE` transaction, so two processes cannot both be granted.
pub fn claim(db: &Db, now: i64) -> Result<Claim> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    db.batch(|| {
        if let Some((since, _)) = read_lease(db)? {
            if now - since < LEASE_SECONDS {
                return Ok(Claim::Busy { since });
            }
        }
        let holder = format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        db.set_text_setting(crate::db::keys::REFRESH_LEASE, &format!("{now} {holder}"))?;
        Ok(Claim::Granted(Lease { holder }))
    })
}

/// Marks `lease` alive as of `now`. A lease that has since expired and
/// been taken by someone else is left to them.
pub fn renew(db: &Db, lease: &Lease, now: i64) -> Result<()> {
    db.batch(|| {
        if read_lease(db)?.is_some_and(|(_, holder)| holder == lease.holder) {
            let value = format!("{now} {}", lease.holder);
            db.set_text_setting(crate::db::keys::REFRESH_LEASE, &value)?;
        }
        Ok(())
    })
}

/// Gives `lease` back, if it is still ours.
pub fn release(db: &Db, lease: &Lease) -> Result<()> {
    db.batch(|| {
        if read_lease(db)?.is_some_and(|(_, holder)| holder == lease.holder) {
            db.set_text_setting(crate::db::keys::REFRESH_LEASE, "")?;
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ReputationSource;

    const T: i64 = 1_790_000_000;

    fn granted(claim: Claim) -> Lease {
        match claim {
            Claim::Granted(lease) => lease,
            Claim::Busy { since } => panic!("refused, held since {since}"),
        }
    }

    /// One download at a time: a second claim is refused, and says since
    /// when, until the first gives the lease back.
    #[test]
    fn a_second_download_waits_until_the_first_releases_the_lease() {
        let db = Db::open_in_memory().unwrap();
        let first = granted(claim(&db, T).unwrap());

        assert_eq!(claim(&db, T + 5).unwrap(), Claim::Busy { since: T });

        release(&db, &first).unwrap();
        granted(claim(&db, T + 6).unwrap());
    }

    /// A holder that died stops holding once it has gone quiet for
    /// `LEASE_SECONDS`; one that keeps renewing keeps it.
    #[test]
    fn a_lease_lapses_only_when_its_holder_stops_renewing() {
        let db = Db::open_in_memory().unwrap();
        let alive = granted(claim(&db, T).unwrap());

        renew(&db, &alive, T + LEASE_SECONDS - 10).unwrap();
        assert!(matches!(
            claim(&db, T + LEASE_SECONDS + 10).unwrap(),
            Claim::Busy { .. }
        ));

        let taken_over = granted(claim(&db, T + 2 * LEASE_SECONDS).unwrap());
        // The old holder waking up does not take it back, or free it.
        renew(&db, &alive, T + 2 * LEASE_SECONDS + 1).unwrap();
        release(&db, &alive).unwrap();
        assert_eq!(
            claim(&db, T + 2 * LEASE_SECONDS + 2).unwrap(),
            Claim::Busy {
                since: T + 2 * LEASE_SECONDS
            }
        );
        release(&db, &taken_over).unwrap();
    }

    /// A finished run marks the weekly job done whatever happened, so it
    /// does not repeat what someone just did by hand, and names what failed.
    #[test]
    fn a_finished_run_is_recorded_against_the_weekly_job() {
        let db = Db::open_in_memory().unwrap();
        let outcomes = vec![
            (
                Source::Country("ru".to_string()),
                Ok("2 range(s)".to_string()),
            ),
            (
                Source::Country("cn".to_string()),
                Err("timed out".to_string()),
            ),
        ];

        let summary = record(&db, &outcomes, "from the Dashboard");

        assert_eq!(
            summary,
            "Updated 1 list(s). 1 failed \u{2014} country cn: timed out"
        );
        assert_eq!(
            db.get_cron_last_summary(crate::cron::CronJob::UpdateEverything.id())
                .unwrap()
                .as_deref(),
            Some(summary.as_str())
        );
    }

    fn feed(id: &str) -> ReputationSource {
        ReputationSource {
            id: id.to_string(),
            name: id.to_string(),
            url: format!("https://example.invalid/{id}"),
            enabled: false,
            last_fetched_at: None,
            range_count: 0,
        }
    }

    /// The button says "everything", so the plan has to actually contain
    /// everything a `batch` run would fetch. A plan that quietly omits a
    /// kind of source leaves the console telling you to go and run a CLI
    /// command — which is the bug this replaced.
    #[test]
    fn the_plan_covers_every_kind_of_downloadable_list() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        db.set_reputation_source_enabled("tor-exits", true).unwrap();
        db.set_country_selected("ru", true).unwrap();

        let plan = plan(&db).unwrap();

        let labels: Vec<String> = plan.iter().map(Source::label).collect();
        for expected in [
            "bot list well-known-bots",
            "crawler ranges googlebot",
            "feed tor-exits",
            "country ru",
        ] {
            assert!(
                labels.iter().any(|l| l == expected),
                "the plan is missing {expected}: {labels:?}"
            );
        }
    }

    /// A feed nobody turned on is not a list this host uses, and fetching
    /// it would fill a table with ranges no rule references.
    #[test]
    fn a_disabled_feed_is_not_in_the_plan() {
        let db = Db::open_in_memory().unwrap();
        db.register_reputation_source(&feed("tor-exits")).unwrap();

        let labels: Vec<String> = plan(&db).unwrap().iter().map(Source::label).collect();

        assert!(
            !labels.iter().any(|l| l == "feed tor-exits"),
            "labels: {labels:?}"
        );
    }

    #[test]
    fn an_unselected_country_is_not_in_the_plan() {
        let db = Db::open_in_memory().unwrap();
        db.replace_country_ranges("nl", &["1.2.3.0/24".to_string()])
            .unwrap();

        let labels: Vec<String> = plan(&db).unwrap().iter().map(Source::label).collect();

        assert!(
            !labels.iter().any(|l| l == "country nl"),
            "having ranges is not the same as being selected: {labels:?}"
        );
    }

    /// A catch-all in a feed is dropped, and the one-line summary a cron
    /// log or the console shows says so — a feed that suddenly carries
    /// `0.0.0.0/0` has been tampered with or broken, and that is news.
    #[test]
    fn a_dropped_catch_all_is_named_in_the_summary() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();

        for source in [
            Source::Country("xx".to_string()),
            Source::Reputation(ReputationSourceKind::FireholLevel1),
        ] {
            let summary = store(&db, &source, "0.0.0.0/0\n5.6.7.0/24\n").unwrap();

            assert!(
                summary.starts_with("1 range(s)")
                    && summary.contains("dropped 1")
                    && summary.contains("0.0.0.0/0"),
                "{} summary was: {summary}",
                source.label()
            );
        }
    }

    /// And a clean feed's summary is unchanged.
    #[test]
    fn a_clean_feed_summary_mentions_no_drops() {
        let db = Db::open_in_memory().unwrap();

        let summary = store(&db, &Source::Country("xx".to_string()), "5.6.7.0/24\n").unwrap();

        assert_eq!(summary, "1 range(s)");
    }

    /// A row whose id this version no longer knows can only come from a
    /// database written by one that did. Skipped, not fatal.
    #[test]
    fn a_feed_this_version_does_not_know_is_skipped_rather_than_failing() {
        let db = Db::open_in_memory().unwrap();
        db.register_reputation_source(&feed("a-feed-we-dropped"))
            .unwrap();
        db.set_reputation_source_enabled("a-feed-we-dropped", true)
            .unwrap();

        let plan = plan(&db).expect("an unknown feed must not fail the whole plan");

        assert!(!plan.iter().any(|s| s.label().contains("dropped")));
    }

    /// The cron treats the three crawler sources as one job, so "done" has
    /// to mean all three — otherwise the front-end skips re-fetching the
    /// one that failed until tomorrow.
    #[test]
    fn one_failed_crawler_source_means_the_cron_job_is_not_done() {
        let ok = (
            Source::CrawlerRanges(IpRangeSourceKind::GoogleBot),
            Ok("1 range".to_string()),
        );
        let failed = (
            Source::CrawlerRanges(IpRangeSourceKind::GptBot),
            Err("timed out".to_string()),
        );
        let unrelated = (
            Source::Country("ru".to_string()),
            Err("timed out".to_string()),
        );

        assert!(crawler_ranges_all_succeeded(std::slice::from_ref(&ok)));
        assert!(!crawler_ranges_all_succeeded(&[ok.clone(), failed]));
        // A country failing says nothing about the crawler job.
        assert!(crawler_ranges_all_succeeded(&[ok, unrelated]));
    }
    /// `store` is the half worth testing: `fetch` is a network call, but a
    /// mistake here parses a real download into nothing and reports
    /// success. One payload per kind, in each upstream's real shape.
    #[test]
    fn store_lands_a_payload_of_every_kind() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::register_all_ip_range_sources(&db).unwrap();
        crate::ipranges::reputation::register_all_reputation_sources(&db).unwrap();
        db.set_reputation_source_enabled("tor-exits", true).unwrap();

        let crawler = Source::CrawlerRanges(IpRangeSourceKind::GoogleBot);
        assert_eq!(
            store(
                &db,
                &crawler,
                r#"{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"}]}"#
            )
            .unwrap(),
            "1 range(s)"
        );
        assert_eq!(
            db.ip_ranges_for_source("googlebot").unwrap(),
            vec!["66.249.64.0/19".to_string()]
        );

        let feed = Source::Reputation(ReputationSourceKind::TorExits);
        assert_eq!(
            store(&db, &feed, "185.220.101.1\n# a comment\n").unwrap(),
            "1 range(s)"
        );
        assert_eq!(
            db.enabled_reputation_ranges().unwrap(),
            vec!["185.220.101.1".to_string()]
        );

        let country = Source::Country("ru".to_string());
        assert_eq!(
            store(&db, &country, "5.8.0.0/19\n5.16.0.0/14\n").unwrap(),
            "2 range(s)"
        );
        // Through the public derived-rules path rather than the private
        // `country_ranges`: what matters is that the ranges reach the
        // firewall, not that a row exists.
        db.set_country_selected("ru", true).unwrap();
        assert_eq!(
            db.derived_firewall_entries()
                .unwrap()
                .iter()
                .filter(|(addr, _)| addr.starts_with("5."))
                .count(),
            2
        );
    }

    /// A bot list goes through its own parser and lands as patterns, not
    /// ranges — the one kind whose `store` writes to a different table.
    #[test]
    fn store_lands_a_bot_list() {
        let db = Db::open_in_memory().unwrap();
        crate::botlist::register_all_sources(&db).unwrap();
        let kind = crate::botlist::SourceKind::AiRobotsTxt;

        let summary = store(
            &db,
            &Source::BotList(kind),
            r#"{"GPTBot": {"operator": "OpenAI"}}"#,
        )
        .unwrap();

        assert!(summary.ends_with("bot(s)"), "was: {summary}");
        assert!(
            db.list_bots()
                .unwrap()
                .iter()
                .any(|bot| bot.name == "GPTBot"),
            "the bot did not land"
        );
    }

    /// Garbage from an upstream is an error, not a silent zero — a feed
    /// that started serving an HTML error page must not read as "updated".
    #[test]
    fn store_rejects_a_payload_it_cannot_parse() {
        let db = Db::open_in_memory().unwrap();
        crate::ipranges::register_all_ip_range_sources(&db).unwrap();

        let err = store(
            &db,
            &Source::CrawlerRanges(IpRangeSourceKind::GoogleBot),
            "<!DOCTYPE html><h1>502 Bad Gateway</h1>",
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("parse"), "was: {err:#}");
    }

    #[test]
    fn every_source_labels_itself() {
        assert_eq!(
            Source::CrawlerRanges(IpRangeSourceKind::GptBot).label(),
            "crawler ranges gptbot"
        );
        assert_eq!(
            Source::Reputation(ReputationSourceKind::Aws).label(),
            "feed aws"
        );
        assert_eq!(Source::Country("ru".to_string()).label(), "country ru");
        assert!(Source::BotList(crate::botlist::SourceKind::AiRobotsTxt)
            .label()
            .starts_with("bot list "));
    }
}
