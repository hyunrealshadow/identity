//! Instance overview use cases.
//!
//! The service owns the captured-time and fixed-range semantics for the
//! read-only dashboard and maps typed storage failures to the existing
//! localized internal error envelope. Each method loads one aggregate so the
//! GraphQL adapter can authorize every protected root independently.

use std::{collections::BTreeMap, sync::Arc};

use chrono::{DateTime, NaiveDate, Utc};
use identity_domain::{
    instance_overview::{
        InstanceDailyCount, InstanceOverviewRepository, InstanceOverviewRepositoryError,
        NewUserWindow, REGISTRATION_WINDOW_DAYS,
    },
    time_zone::TimeZone,
};

use crate::error::{
    AppError,
    codes::{common::CommonErrorCode, user_management::UserManagementErrorCode},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceDailyCountView {
    pub date: NaiveDate,
    pub count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceUserOverviewView {
    pub total: i32,
    pub enabled: i32,
    pub created_last_7_days: i32,
    pub registrations: Vec<InstanceDailyCountView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceApplicationOverviewView {
    pub total: i32,
    pub enabled: i32,
    pub built_in: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSessionOverviewView {
    pub active: i32,
    pub created_last_24_hours: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceResourceOverviewView {
    pub total: i32,
    pub enabled: i32,
}

pub struct InstanceOverviewService {
    repository: Arc<dyn InstanceOverviewRepository>,
}

impl InstanceOverviewService {
    #[must_use]
    pub fn new(repository: Arc<dyn InstanceOverviewRepository>) -> Self {
        Self { repository }
    }

    #[tracing::instrument(skip_all, name = "instance_overview.users")]
    pub async fn user_overview(
        &self,
        generated_at: DateTime<Utc>,
        time_zone: &str,
    ) -> Result<InstanceUserOverviewView, AppError> {
        let time_zone = TimeZone::parse(time_zone).map_err(|_| {
            AppError::from_code(UserManagementErrorCode::ValidationFailed).with_field_error(
                "timeZone",
                AppError::from_code(CommonErrorCode::InvalidTimeZone),
            )
        })?;
        let window = NewUserWindow::ending_at_in_zone(generated_at, time_zone);
        let counts = self
            .repository
            .user_counts(window)
            .await
            .map_err(AppError::from)?;

        let mut observed: BTreeMap<NaiveDate, i64> = counts
            .registrations
            .into_iter()
            .map(|InstanceDailyCount { date, count }| (date, count))
            .collect();
        let mut created_last_7_days = 0_i64;
        let mut registrations = Vec::with_capacity(REGISTRATION_WINDOW_DAYS);
        for date in window.bucket_dates() {
            let count = observed.remove(&date).unwrap_or(0);
            created_last_7_days = created_last_7_days
                .checked_add(count)
                .ok_or_else(|| count_out_of_range("users.created_last_7_days"))?;
            registrations.push(InstanceDailyCountView {
                date,
                count: checked_count("users.registrations", count)?,
            });
        }

        Ok(InstanceUserOverviewView {
            total: checked_count("users.total", counts.total)?,
            enabled: checked_count("users.enabled", counts.enabled)?,
            created_last_7_days: checked_count("users.created_last_7_days", created_last_7_days)?,
            registrations,
        })
    }

    #[tracing::instrument(skip_all, name = "instance_overview.applications")]
    pub async fn application_overview(&self) -> Result<InstanceApplicationOverviewView, AppError> {
        let counts = self
            .repository
            .application_counts()
            .await
            .map_err(AppError::from)?;
        Ok(InstanceApplicationOverviewView {
            total: checked_count("applications.total", counts.total)?,
            enabled: checked_count("applications.enabled", counts.enabled)?,
            built_in: checked_count("applications.built_in", counts.built_in)?,
        })
    }

    #[tracing::instrument(skip_all, name = "instance_overview.sessions")]
    pub async fn session_overview(
        &self,
        generated_at: DateTime<Utc>,
    ) -> Result<InstanceSessionOverviewView, AppError> {
        let counts = self
            .repository
            .session_counts(generated_at)
            .await
            .map_err(AppError::from)?;
        Ok(InstanceSessionOverviewView {
            active: checked_count("sessions.active", counts.active)?,
            created_last_24_hours: checked_count(
                "sessions.created_last_24_hours",
                counts.created_last_24_hours,
            )?,
        })
    }

    #[tracing::instrument(skip_all, name = "instance_overview.resources")]
    pub async fn resource_overview(&self) -> Result<InstanceResourceOverviewView, AppError> {
        let counts = self
            .repository
            .resource_counts()
            .await
            .map_err(AppError::from)?;
        Ok(InstanceResourceOverviewView {
            total: checked_count("resources.total", counts.total)?,
            enabled: checked_count("resources.enabled", counts.enabled)?,
        })
    }
}

fn checked_count(metric: &'static str, value: i64) -> Result<i32, AppError> {
    i32::try_from(value).map_err(|_| count_out_of_range(metric))
}

fn count_out_of_range(metric: &'static str) -> AppError {
    AppError::internal(InstanceOverviewRepositoryError::CountOutOfRange { metric })
}

impl From<InstanceOverviewRepositoryError> for AppError {
    fn from(error: InstanceOverviewRepositoryError) -> Self {
        AppError::internal(error)
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Error, sync::Arc};

    use async_trait::async_trait;
    use chrono::{DateTime, NaiveDate, Utc};
    use identity_domain::instance_overview::{
        InstanceApplicationCounts, InstanceDailyCount, InstanceOverviewRepository,
        InstanceOverviewRepositoryError, InstanceResourceCounts, InstanceSessionCounts,
        InstanceUserCounts, NewUserWindow,
    };

    use super::InstanceOverviewService;
    use crate::error::kind::ErrorKind;

    struct StubRepository {
        users: Result<InstanceUserCounts, InstanceOverviewRepositoryError>,
    }

    #[async_trait]
    impl InstanceOverviewRepository for StubRepository {
        async fn user_counts(
            &self,
            _window: NewUserWindow,
        ) -> Result<InstanceUserCounts, InstanceOverviewRepositoryError> {
            match &self.users {
                Ok(counts) => Ok(counts.clone()),
                Err(_) => Err(InstanceOverviewRepositoryError::QueryFailed(Box::new(
                    Error::other("storage unavailable"),
                ))),
            }
        }

        async fn application_counts(
            &self,
        ) -> Result<InstanceApplicationCounts, InstanceOverviewRepositoryError> {
            Ok(InstanceApplicationCounts {
                total: 0,
                enabled: 0,
                built_in: 0,
            })
        }

        async fn session_counts(
            &self,
            _generated_at: DateTime<Utc>,
        ) -> Result<InstanceSessionCounts, InstanceOverviewRepositoryError> {
            Ok(InstanceSessionCounts {
                active: 0,
                created_last_24_hours: 0,
            })
        }

        async fn resource_counts(
            &self,
        ) -> Result<InstanceResourceCounts, InstanceOverviewRepositoryError> {
            Ok(InstanceResourceCounts {
                total: 0,
                enabled: 0,
            })
        }
    }

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn day(rfc3339: &str) -> NaiveDate {
        at(rfc3339).date_naive()
    }

    #[tokio::test]
    async fn registrations_are_zero_filled_and_sum_to_the_window_total() {
        let repository = Arc::new(StubRepository {
            users: Ok(InstanceUserCounts {
                total: 4,
                enabled: 3,
                registrations: vec![
                    InstanceDailyCount {
                        date: day("2026-10-16T00:00:00Z"),
                        count: 1,
                    },
                    InstanceDailyCount {
                        date: day("2026-10-19T00:00:00Z"),
                        count: 2,
                    },
                ],
            }),
        });
        let service = InstanceOverviewService::new(repository);

        let overview = service
            .user_overview(at("2026-10-22T13:45:12Z"), "UTC")
            .await
            .unwrap();

        assert_eq!(overview.total, 4);
        assert_eq!(overview.enabled, 3);
        assert_eq!(overview.created_last_7_days, 3);
        assert_eq!(
            overview
                .registrations
                .iter()
                .map(|bucket| bucket.date)
                .collect::<Vec<_>>(),
            vec![
                day("2026-10-16T00:00:00Z"),
                day("2026-10-17T00:00:00Z"),
                day("2026-10-18T00:00:00Z"),
                day("2026-10-19T00:00:00Z"),
                day("2026-10-20T00:00:00Z"),
                day("2026-10-21T00:00:00Z"),
                day("2026-10-22T00:00:00Z"),
            ]
        );
        assert_eq!(
            overview
                .registrations
                .iter()
                .map(|bucket| bucket.count)
                .collect::<Vec<_>>(),
            vec![1, 0, 0, 2, 0, 0, 0]
        );
        assert_eq!(
            overview
                .registrations
                .iter()
                .map(|bucket| bucket.count)
                .sum::<i32>(),
            overview.created_last_7_days
        );
    }

    #[tokio::test]
    async fn a_count_that_does_not_fit_graphql_int_fails_internally() {
        let repository = Arc::new(StubRepository {
            users: Ok(InstanceUserCounts {
                total: i64::from(i32::MAX) + 1,
                enabled: 0,
                registrations: Vec::new(),
            }),
        });
        let service = InstanceOverviewService::new(repository);

        let error = service
            .user_overview(at("2026-10-22T13:45:12Z"), "UTC")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Internal);
    }

    #[tokio::test]
    async fn invalid_time_zone_is_a_localized_field_error() {
        let service = InstanceOverviewService::new(Arc::new(StubRepository {
            users: Ok(InstanceUserCounts {
                total: 0,
                enabled: 0,
                registrations: Vec::new(),
            }),
        }));

        let error = service
            .user_overview(at("2026-10-22T13:45:12Z"), "+02:00")
            .await
            .unwrap_err();

        assert_eq!(error.kind(), ErrorKind::Validation);
        assert_eq!(error.code(), 16000);
        let field = &error.validation().unwrap().fields()[0];
        assert_eq!(field.field(), "timeZone");
        assert_eq!(field.code(), 10010);
    }
}
