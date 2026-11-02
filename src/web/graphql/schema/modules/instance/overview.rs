//! Read-only instance overview GraphQL surface.
//!
//! The container captures one timestamp and exposes only that value. Every
//! protected aggregate is a nullable nested field whose native management
//! guard runs before the resolver loads its own aggregate.

use crate::graphql::schema::access::access;
use async_graphql::{Context, Object, Result, SimpleObject};
use chrono::{DateTime, NaiveDate, Utc};
use identity_application::{
    authorization::ManagementTarget,
    instance_overview::{
        InstanceApplicationOverviewView, InstanceDailyCountView, InstanceResourceOverviewView,
        InstanceSessionOverviewView, InstanceUserOverviewView,
    },
};
use identity_domain::authorization::ManagementScope;

use crate::graphql::schema::{
    authorization::request_context, error::app_error, management_guard::ManagementGuard,
};

pub(crate) struct InstanceOverview {
    generated_at: DateTime<Utc>,
}

impl InstanceOverview {
    pub(crate) fn new(generated_at: DateTime<Utc>) -> Self {
        Self { generated_at }
    }
}

#[Object]
impl InstanceOverview {
    #[graphql(name = "generatedAt")]
    async fn generated_at(&self) -> DateTime<Utc> {
        self.generated_at
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::UsersRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::UsersRead)),
        complexity = 10
    )]
    async fn users(
        &self,
        ctx: &Context<'_>,
        #[graphql(name = "timeZone", default = "UTC")] time_zone: String,
    ) -> Result<Option<InstanceUserOverview>> {
        let request = request_context(ctx)?;
        let view = request
            .state
            .services()
            .instance_overview()
            .user_overview(self.generated_at, &time_zone)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(Some(InstanceUserOverview::from(view)))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ClientsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ClientsRead)),
        complexity = 10
    )]
    async fn applications(&self, ctx: &Context<'_>) -> Result<Option<InstanceApplicationOverview>> {
        let request = request_context(ctx)?;
        let view = request
            .state
            .services()
            .instance_overview()
            .application_overview()
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(Some(InstanceApplicationOverview::from(view)))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::SessionsRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::SessionsRead)),
        complexity = 20
    )]
    async fn sessions(&self, ctx: &Context<'_>) -> Result<Option<InstanceSessionOverview>> {
        let request = request_context(ctx)?;
        let view = request
            .state
            .services()
            .instance_overview()
            .session_overview(self.generated_at)
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(Some(InstanceSessionOverview::from(view)))
    }

    #[graphql(
        guard = "ManagementGuard::new(ManagementScope::ResourcesRead, ManagementTarget::instance())",
        directive = access::apply(ManagementGuard::policy(ManagementScope::ResourcesRead)),
        complexity = 10
    )]
    async fn resources(&self, ctx: &Context<'_>) -> Result<Option<InstanceResourceOverview>> {
        let request = request_context(ctx)?;
        let view = request
            .state
            .services()
            .instance_overview()
            .resource_overview()
            .await
            .map_err(|error| app_error(ctx, error))?;
        Ok(Some(InstanceResourceOverview::from(view)))
    }
}

#[derive(SimpleObject)]
pub(crate) struct InstanceUserOverview {
    total: i32,
    enabled: i32,
    #[graphql(name = "createdLast7Days")]
    created_last_7_days: i32,
    registrations: Vec<InstanceDailyCount>,
}

#[derive(SimpleObject)]
pub(crate) struct InstanceDailyCount {
    date: NaiveDate,
    count: i32,
}

#[derive(SimpleObject)]
pub(crate) struct InstanceApplicationOverview {
    total: i32,
    enabled: i32,
    #[graphql(name = "builtIn")]
    built_in: i32,
}

#[derive(SimpleObject)]
pub(crate) struct InstanceSessionOverview {
    active: i32,
    #[graphql(name = "createdLast24Hours")]
    created_last_24_hours: i32,
}

#[derive(SimpleObject)]
pub(crate) struct InstanceResourceOverview {
    total: i32,
    enabled: i32,
}

impl From<InstanceUserOverviewView> for InstanceUserOverview {
    fn from(view: InstanceUserOverviewView) -> Self {
        Self {
            total: view.total,
            enabled: view.enabled,
            created_last_7_days: view.created_last_7_days,
            registrations: view
                .registrations
                .into_iter()
                .map(InstanceDailyCount::from)
                .collect(),
        }
    }
}

impl From<InstanceDailyCountView> for InstanceDailyCount {
    fn from(view: InstanceDailyCountView) -> Self {
        Self {
            date: view.date,
            count: view.count,
        }
    }
}

impl From<InstanceApplicationOverviewView> for InstanceApplicationOverview {
    fn from(view: InstanceApplicationOverviewView) -> Self {
        Self {
            total: view.total,
            enabled: view.enabled,
            built_in: view.built_in,
        }
    }
}

impl From<InstanceSessionOverviewView> for InstanceSessionOverview {
    fn from(view: InstanceSessionOverviewView) -> Self {
        Self {
            active: view.active,
            created_last_24_hours: view.created_last_24_hours,
        }
    }
}

impl From<InstanceResourceOverviewView> for InstanceResourceOverview {
    fn from(view: InstanceResourceOverviewView) -> Self {
        Self {
            total: view.total,
            enabled: view.enabled,
        }
    }
}
