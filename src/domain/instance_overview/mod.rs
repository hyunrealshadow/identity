//! Read-only instance overview aggregates.
//!
//! This module models the instance dashboard's aggregate values and the
//! repository port that produces them. It has no SQL, HTTP or GraphQL types so
//! the application and adapters can share the same bounded semantics.

use std::{array, error::Error as StdError};

use async_trait::async_trait;
use chrono::{
    DateTime, Days, Duration, LocalResult, NaiveDate, NaiveDateTime, NaiveTime, TimeZone as _, Utc,
};
use thiserror::Error;

use crate::time_zone::TimeZone;

/// Number of calendar buckets in the new-user registration series.
pub const REGISTRATION_WINDOW_DAYS: usize = 7;

/// Inclusive lower / exclusive upper timestamp bounds for new-user counts.
///
/// The window always starts at the first valid local instant six calendar days
/// before the local calendar day containing [`Self::end`] and ends at the
/// captured container timestamp. Instants are stored in UTC, while bucket dates
/// stay local to [`Self::time_zone`]. The upper bound is exclusive so the series
/// cannot include users created after the dashboard container was generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewUserWindow {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub time_zone: TimeZone,
    start_date: NaiveDate,
}

impl NewUserWindow {
    /// UTC window retained for existing callers and tests.
    #[must_use]
    pub fn ending_at(end: DateTime<Utc>) -> Self {
        Self::ending_at_in_zone(end, TimeZone::utc())
    }

    /// Derive the window from the local calendar date in `time_zone`.
    ///
    /// The start is the earliest real instant belonging to the local start
    /// date. For a skipped local midnight it is the first instant after the DST
    /// gap; for an ambiguous midnight the earlier occurrence is chosen.
    #[must_use]
    pub fn ending_at_in_zone(end: DateTime<Utc>, time_zone: TimeZone) -> Self {
        let tz = time_zone.as_tz();
        let end_date = end.with_timezone(&tz).date_naive();
        let start_date = end_date - Days::new(REGISTRATION_WINDOW_DAYS as u64 - 1);
        Self {
            start: first_valid_local_instant(time_zone, start_date),
            end,
            time_zone,
            start_date,
        }
    }

    /// Exactly seven ascending local dates: six previous calendar days plus
    /// the local calendar day containing [`Self::end`].
    #[must_use]
    pub fn bucket_dates(&self) -> [NaiveDate; REGISTRATION_WINDOW_DAYS] {
        array::from_fn(|offset| self.start_date + Days::new(offset as u64))
    }
}

fn first_valid_local_instant(time_zone: TimeZone, date: NaiveDate) -> DateTime<Utc> {
    let tz = time_zone.as_tz();
    let midnight = date.and_time(NaiveTime::MIN);
    if let Some(instant) = resolve_earliest(tz, midnight) {
        return instant;
    }

    // Midnight is inside a DST gap. Walk forward to the first local minute that
    // actually exists on this date. Gaps in the IANA database are at most a few
    // hours, never a full normal day.
    for minutes in 1..(24 * 60) {
        let candidate = midnight + Duration::minutes(minutes);
        if candidate.date() != date {
            break;
        }
        if let Some(instant) = resolve_earliest(tz, candidate) {
            return instant;
        }
    }

    // A whole local date can be skipped by a jurisdiction. Use the next valid
    // local instant so the window still has a real UTC start.
    for offset in 1..=2 {
        let next_date = date + Days::new(offset);
        if let Some(instant) = resolve_earliest(tz, next_date.and_time(NaiveTime::MIN)) {
            return instant;
        }
    }
    date.and_time(NaiveTime::MIN).and_utc()
}

fn resolve_earliest(tz: chrono_tz::Tz, local: NaiveDateTime) -> Option<DateTime<Utc>> {
    match tz.from_local_datetime(&local) {
        LocalResult::Single(instant) => Some(instant.with_timezone(&Utc)),
        LocalResult::Ambiguous(first, second) => Some(first.min(second).with_timezone(&Utc)),
        LocalResult::None => None,
    }
}

/// One local calendar-day bucket. A zero count is a real observed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceDailyCount {
    pub date: NaiveDate,
    pub count: i64,
}

/// Raw user aggregate returned by storage. `registrations` contains only dates
/// that have at least one matching row; the application layer zero-fills the
/// fixed seven-day series.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceUserCounts {
    pub total: i64,
    pub enabled: i64,
    pub registrations: Vec<InstanceDailyCount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceClientCounts {
    pub total: i64,
    pub enabled: i64,
    pub built_in: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSessionCounts {
    pub active: i64,
    pub created_last_24_hours: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceResourceCounts {
    pub total: i64,
    pub enabled: i64,
}

#[derive(Debug, Error)]
pub enum InstanceOverviewRepositoryError {
    #[error("failed to query instance overview aggregate")]
    QueryFailed(#[source] Box<dyn StdError + Send + Sync>),

    /// The database count cannot be represented by the GraphQL `Int` scalar.
    #[error("instance overview count is outside the supported integer range: {metric}")]
    CountOutOfRange { metric: &'static str },
}

/// Aggregate read port for the instance overview.
///
/// Each method loads exactly one protected aggregate. Callers must authorize
/// the corresponding management scope before invoking it.
#[async_trait]
pub trait InstanceOverviewRepository: Send + Sync {
    async fn user_counts(
        &self,
        window: NewUserWindow,
    ) -> Result<InstanceUserCounts, InstanceOverviewRepositoryError>;

    async fn client_counts(&self) -> Result<InstanceClientCounts, InstanceOverviewRepositoryError>;

    /// `generated_at` is the same instant captured by the overview container.
    async fn session_counts(
        &self,
        generated_at: DateTime<Utc>,
    ) -> Result<InstanceSessionCounts, InstanceOverviewRepositoryError>;

    async fn resource_counts(
        &self,
    ) -> Result<InstanceResourceCounts, InstanceOverviewRepositoryError>;
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, NaiveDate, Utc};

    use super::{NewUserWindow, REGISTRATION_WINDOW_DAYS, first_valid_local_instant};
    use crate::time_zone::TimeZone;

    fn at(rfc3339: &str) -> chrono::DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn date(year: i32, month: u32, day: u32) -> chrono::NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    #[test]
    fn window_starts_at_utc_midnight_six_days_before_the_generated_day() {
        let end = at("2026-10-22T13:45:12Z");
        let window = NewUserWindow::ending_at(end);

        assert_eq!(window.start, at("2026-10-16T00:00:00Z"));
        assert_eq!(window.end, end);
    }

    #[test]
    fn bucket_dates_are_exactly_seven_ascending_utc_days_ending_today() {
        let window = NewUserWindow::ending_at(at("2026-10-22T13:45:12Z"));
        let dates = window.bucket_dates();

        assert_eq!(dates.len(), REGISTRATION_WINDOW_DAYS);
        assert_eq!(dates[0], at("2026-10-16T00:00:00Z").date_naive());
        assert_eq!(dates[6], at("2026-10-22T00:00:00Z").date_naive());
        assert!(dates.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn window_does_not_depend_on_the_time_of_day_inside_the_final_bucket() {
        let early = NewUserWindow::ending_at(at("2026-10-22T00:00:00Z"));
        let late = NewUserWindow::ending_at(at("2026-10-22T23:59:59Z"));

        assert_eq!(early.start, late.start);
        assert_eq!(early.bucket_dates(), late.bucket_dates());
    }

    #[test]
    fn positive_offset_uses_the_local_calendar_date() {
        let end = at("2026-10-22T13:45:12Z");
        let window = NewUserWindow::ending_at_in_zone(end, TimeZone::parse("Asia/Tokyo").unwrap());

        assert_eq!(window.start, at("2026-10-15T15:00:00Z"));
        assert_eq!(window.end, end);
        assert_eq!(window.time_zone.name(), "Asia/Tokyo");
        assert_eq!(
            window.bucket_dates(),
            [
                date(2026, 10, 16),
                date(2026, 10, 17),
                date(2026, 10, 18),
                date(2026, 10, 19),
                date(2026, 10, 20),
                date(2026, 10, 21),
                date(2026, 10, 22),
            ]
        );
    }

    #[test]
    fn negative_offset_uses_the_local_calendar_date() {
        let end = at("2026-10-22T13:45:12Z");
        let window =
            NewUserWindow::ending_at_in_zone(end, TimeZone::parse("America/Los_Angeles").unwrap());

        assert_eq!(window.start, at("2026-10-16T07:00:00Z"));
        assert_eq!(window.end, end);
        assert_eq!(
            window.bucket_dates(),
            [
                date(2026, 10, 16),
                date(2026, 10, 17),
                date(2026, 10, 18),
                date(2026, 10, 19),
                date(2026, 10, 20),
                date(2026, 10, 21),
                date(2026, 10, 22),
            ]
        );
    }

    #[test]
    fn us_dst_days_are_23_and_25_hours_between_local_midnights() {
        let zone = TimeZone::parse("America/Los_Angeles").unwrap();

        let spring_start = first_valid_local_instant(zone, date(2026, 3, 8));
        let spring_next = first_valid_local_instant(zone, date(2026, 3, 9));
        assert_eq!(spring_start, at("2026-03-08T08:00:00Z"));
        assert_eq!(spring_next, at("2026-03-09T07:00:00Z"));
        assert_eq!(spring_next - spring_start, Duration::hours(23));

        let fall_start = first_valid_local_instant(zone, date(2026, 11, 1));
        let fall_next = first_valid_local_instant(zone, date(2026, 11, 2));
        assert_eq!(fall_start, at("2026-11-01T07:00:00Z"));
        assert_eq!(fall_next, at("2026-11-02T08:00:00Z"));
        assert_eq!(fall_next - fall_start, Duration::hours(25));
    }

    #[test]
    fn a_dst_window_keeps_seven_local_bucket_dates_across_the_transition() {
        let end = at("2026-03-11T12:00:00Z");
        let window =
            NewUserWindow::ending_at_in_zone(end, TimeZone::parse("America/Los_Angeles").unwrap());

        assert_eq!(window.start, at("2026-03-05T08:00:00Z"));
        assert_eq!(
            window.bucket_dates(),
            [
                date(2026, 3, 5),
                date(2026, 3, 6),
                date(2026, 3, 7),
                date(2026, 3, 8),
                date(2026, 3, 9),
                date(2026, 3, 10),
                date(2026, 3, 11),
            ]
        );
    }
}
