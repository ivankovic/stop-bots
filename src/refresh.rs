/*  This file is part of the stop-bots project.
 *
 *  Copyright (C) 2026 Marko Ivankovic
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
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
            let bots = kind.parse(raw)?;
            let count = botlist::store(db, *kind, &bots)?;
            Ok(format!("{count} bot(s)"))
        }
        Source::CrawlerRanges(kind) => {
            let cidrs = kind.parse(raw)?;
            let count = ipranges::store(db, *kind, &cidrs)?;
            Ok(format!("{count} range(s)"))
        }
        Source::Reputation(kind) => {
            let cidrs = kind.parse(raw)?;
            let count = ipranges::reputation::store(db, *kind, &cidrs)?;
            Ok(format!("{count} range(s)"))
        }
        Source::Country(code) => {
            let count = ipranges::store_country(db, code, raw)?;
            Ok(format!("{count} range(s)"))
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::ReputationSource;

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
