//! Request-scoped actor identity.
//!
//! `request_id` is the request correlation identifier returned in GraphQL
//! extensions and response headers. It is not a distributed trace ID. Trace
//! identifiers are optional and carried separately so audit and observability
//! can correlate without conflating the two.

use std::{fmt, time::Duration};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{client::model::ClientOid, user::UserOid};

/// Correlation identifier with the same bounded character set as the trusted
/// request-ID contract.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, ActorContextError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ActorContextError::InvalidRequestId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// W3C trace identifier. Kept optional because a request may have no valid
/// incoming trace context.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct TraceId(String);

impl TraceId {
    pub fn new(value: impl Into<String>) -> Result<Self, ActorContextError> {
        let value = value.into();
        if value.len() != 32
            || value.bytes().all(|byte| byte == b'0')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ActorContextError::InvalidTraceId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthenticationAssurance {
    Aal1,
    Aal2,
}

impl AuthenticationAssurance {
    #[must_use]
    pub const fn is_aal2(self) -> bool {
        matches!(self, Self::Aal2)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Aal1 => "aal1",
            Self::Aal2 => "aal2",
        }
    }
}

/// Human authentication facts used by policy. Machine actors never construct
/// this value and therefore cannot claim a human assurance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanAuthenticationContext {
    pub assurance: AuthenticationAssurance,
    pub auth_time: Option<DateTime<Utc>>,
}

impl HumanAuthenticationContext {
    #[must_use]
    pub const fn new(assurance: AuthenticationAssurance, auth_time: Option<DateTime<Utc>>) -> Self {
        Self {
            assurance,
            auth_time,
        }
    }

    #[must_use]
    pub const fn aal1(auth_time: Option<DateTime<Utc>>) -> Self {
        Self::new(AuthenticationAssurance::Aal1, auth_time)
    }

    #[must_use]
    pub const fn aal2(auth_time: Option<DateTime<Utc>>) -> Self {
        Self::new(AuthenticationAssurance::Aal2, auth_time)
    }

    #[must_use]
    pub fn meets_aal2(self) -> bool {
        self.assurance.is_aal2()
    }

    /// A recent requirement always implies AAL2; an old AAL2 session is not
    /// recent. Future timestamps are rejected conservatively.
    #[must_use]
    pub fn is_recent_aal2(self, now: DateTime<Utc>, max_age: Duration) -> bool {
        if !self.meets_aal2() {
            return false;
        }
        let Some(auth_time) = self.auth_time else {
            return false;
        };
        let age = now.signed_duration_since(auth_time).num_seconds();
        age >= 0 && age <= max_age.as_secs().min(i64::MAX as u64) as i64
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Client,
}

impl PrincipalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Client => "client",
        }
    }
}

/// Distinct principal kinds. A client OID is never looked up as a user OID and
/// a user can never present itself as a machine management principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorPrincipal {
    User {
        user_oid: UserOid,
        authentication: HumanAuthenticationContext,
    },
    Client {
        client_oid: ClientOid,
    },
}

impl ActorPrincipal {
    #[must_use]
    pub fn kind(&self) -> PrincipalKind {
        match self {
            Self::User { .. } => PrincipalKind::User,
            Self::Client { .. } => PrincipalKind::Client,
        }
    }

    #[must_use]
    pub fn oid(&self) -> Uuid {
        match self {
            Self::User { user_oid, .. } => user_oid.0,
            Self::Client { client_oid } => *client_oid,
        }
    }

    #[must_use]
    pub fn as_user(&self) -> Option<(UserOid, HumanAuthenticationContext)> {
        match self {
            Self::User {
                user_oid,
                authentication,
            } => Some((*user_oid, *authentication)),
            Self::Client { .. } => None,
        }
    }

    #[must_use]
    pub fn as_client(&self) -> Option<ClientOid> {
        match self {
            Self::Client { client_oid } => Some(*client_oid),
            Self::User { .. } => None,
        }
    }

    #[must_use]
    pub fn human_authentication(&self) -> Option<HumanAuthenticationContext> {
        match self {
            Self::User { authentication, .. } => Some(*authentication),
            Self::Client { .. } => None,
        }
    }

    #[must_use]
    pub fn is_human(&self) -> bool {
        matches!(self, Self::User { .. })
    }

    #[must_use]
    pub fn is_machine(&self) -> bool {
        matches!(self, Self::Client { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorContext {
    pub principal: ActorPrincipal,
    pub request_id: RequestId,
    pub trace_id: Option<TraceId>,
}

impl ActorContext {
    #[must_use]
    pub fn for_user(
        user_oid: UserOid,
        authentication: HumanAuthenticationContext,
        request_id: RequestId,
        trace_id: Option<TraceId>,
    ) -> Self {
        Self {
            principal: ActorPrincipal::User {
                user_oid,
                authentication,
            },
            request_id,
            trace_id,
        }
    }

    #[must_use]
    pub fn for_client(
        client_oid: ClientOid,
        request_id: RequestId,
        trace_id: Option<TraceId>,
    ) -> Self {
        Self {
            principal: ActorPrincipal::Client { client_oid },
            request_id,
            trace_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ActorContextError {
    #[error("request id must be 1-64 characters from [A-Za-z0-9._-]")]
    InvalidRequestId,
    #[error("trace id must be 32 lowercase hexadecimal characters")]
    InvalidTraceId,
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    use super::{
        ActorContext, ActorContextError, ActorPrincipal, AuthenticationAssurance,
        HumanAuthenticationContext, RequestId, TraceId,
    };

    fn at(seconds: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_opt(seconds, 0).single().unwrap()
    }

    #[test]
    fn request_and_trace_identifiers_have_distinct_contracts() {
        assert!(RequestId::new("01HX-request_1").is_ok());
        assert!(RequestId::new("").is_err());
        assert!(RequestId::new("bad request").is_err());
        assert!(TraceId::new("4bf92f3577b34da6a3ce929d0e0e4736").is_ok());
        assert!(TraceId::new("4BF92F3577B34DA6A3CE929D0E0E4736").is_err());
        assert_eq!(
            TraceId::new("not-a-trace").unwrap_err(),
            ActorContextError::InvalidTraceId
        );
    }

    #[test]
    fn machine_principals_never_carry_human_assurance() {
        let actor =
            ActorContext::for_client(Uuid::new_v4(), RequestId::new("request-1").unwrap(), None);
        assert!(matches!(actor.principal, ActorPrincipal::Client { .. }));
        assert!(actor.principal.human_authentication().is_none());
        assert!(actor.principal.as_user().is_none());
        assert!(actor.principal.is_machine());
    }

    #[test]
    fn recent_aal2_requires_aal2_and_a_fresh_past_auth_time() {
        let now = at(1_000);
        let ttl = std::time::Duration::from_secs(30);
        assert!(HumanAuthenticationContext::aal2(Some(at(990))).is_recent_aal2(now, ttl));
        assert!(!HumanAuthenticationContext::aal2(Some(at(900))).is_recent_aal2(now, ttl));
        assert!(!HumanAuthenticationContext::aal1(Some(at(999))).is_recent_aal2(now, ttl));
        assert!(!HumanAuthenticationContext::aal2(None).is_recent_aal2(now, ttl));
        assert!(!HumanAuthenticationContext::aal2(Some(at(1_010))).is_recent_aal2(now, ttl));
        assert_eq!(
            HumanAuthenticationContext::aal2(None).assurance,
            AuthenticationAssurance::Aal2
        );
    }
}
