use std::{future::Future, net::IpAddr};

use identity_domain::authorization::ActorContext;

/// Client facts of an inbound request attached to transactional audit records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditRequestContext {
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
}

tokio::task_local! {
    static ACTOR: ActorContext;
    static REQUEST: AuditRequestContext;
    static SYSTEM: ();
}

/// Attribute audit records written by `future` to an authenticated actor.
pub async fn with_actor<F: Future>(actor: ActorContext, future: F) -> F::Output {
    ACTOR.scope(actor, future).await
}

/// Attach the inbound request's client facts to audit records.
pub async fn with_request<F: Future>(request: AuditRequestContext, future: F) -> F::Output {
    REQUEST.scope(request, future).await
}

/// Attribute audit records written by `future` to Identity itself, for seed
/// reconciliation and installation bootstrap.
pub async fn as_system<F: Future>(future: F) -> F::Output {
    SYSTEM.scope((), future).await
}

/// Return the active task-local actor, if inside a [`with_actor`] scope.
#[must_use]
pub fn current_actor() -> Option<ActorContext> {
    ACTOR.try_with(Clone::clone).ok()
}

/// Return the active task-local request context, or defaults outside [`with_request`].
#[must_use]
pub fn current_request() -> AuditRequestContext {
    REQUEST.try_with(Clone::clone).unwrap_or_default()
}

/// Whether the current future runs inside an [`as_system`] scope.
#[must_use]
pub fn is_system() -> bool {
    SYSTEM.try_with(|()| ()).is_ok()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use identity_domain::{
        authorization::{
            ActorContext, ActorPrincipal, HumanAuthenticationContext, RequestId, TraceId,
        },
        user::UserOid,
    };
    use uuid::Uuid;

    use super::{
        AuditRequestContext, as_system, current_actor, current_request, is_system, with_actor,
        with_request,
    };

    #[tokio::test]
    async fn task_locals_expose_scoped_context_and_revert_outside_scope() {
        assert!(current_actor().is_none());
        assert_eq!(current_request(), AuditRequestContext::default());
        assert!(!is_system());

        let actor = ActorContext {
            principal: ActorPrincipal::User {
                user_oid: UserOid(Uuid::new_v4()),
                authentication: HumanAuthenticationContext::aal1(None),
            },
            request_id: RequestId::new("req-1").unwrap(),
            trace_id: Some(TraceId::new("0123456789abcdef0123456789abcdef").unwrap()),
        };
        let req = AuditRequestContext {
            ip_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            user_agent: Some("identity-test/1.0".to_owned()),
        };

        with_actor(actor.clone(), async {
            assert_eq!(
                current_actor().as_ref().map(|a| &a.request_id),
                Some(&actor.request_id)
            );
            assert_eq!(
                current_actor().as_ref().and_then(|a| a.trace_id.as_ref()),
                actor.trace_id.as_ref()
            );
        })
        .await;
        assert!(current_actor().is_none());

        with_request(req.clone(), async {
            assert_eq!(current_request(), req);
        })
        .await;
        assert_eq!(current_request(), AuditRequestContext::default());

        as_system(async {
            assert!(is_system());
        })
        .await;
        assert!(!is_system());
    }
}
