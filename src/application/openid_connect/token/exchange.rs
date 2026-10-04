use super::*;
use identity_domain::auth::SessionOid;

impl TokenService {
    pub(super) async fn protected_session_id(
        &self,
        session_oid: SessionOid,
        existing: Option<&str>,
    ) -> Result<String, AppError> {
        if let Some(existing) = existing {
            return Ok(existing.to_string());
        }

        self.data_protector
            .protect("session-id", Uuid::from(session_oid).as_bytes())
            .await
            .map_err(|error| {
                AppError::from_code(TokenErrorCode::DeserializeCodeFailed).with_source(error)
            })
    }
}

pub(crate) fn resolve_client_id(
    client_id: Option<String>,
    client_assertion_type: Option<identity_domain::openid_connect::ClientAssertionType>,
    client_assertion: Option<&str>,
) -> Result<String, AppError> {
    if let Some(client_id) = client_id {
        return Ok(client_id);
    }

    if client_assertion_type
        == Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer)
        && let Some(assertion) = client_assertion
    {
        return client_id_from_assertion(assertion);
    }

    Err(AppError::from_code(TokenErrorCode::ClientIdRequired))
}

/// Bounded outcome/reason categories for issuance result events. The numeric
/// error code carries the specific cause; free-form error text never becomes a
/// metric or event name.
pub(super) fn issuance_result(error: &AppError) -> (&'static str, &'static str) {
    match error.kind() {
        crate::error::kind::ErrorKind::Internal => ("failure", "system_error"),
        crate::error::kind::ErrorKind::Unauthorized => ("rejected", "client_authentication"),
        crate::error::kind::ErrorKind::Forbidden => ("rejected", "forbidden"),
        crate::error::kind::ErrorKind::Conflict => ("rejected", "grant_conflict"),
        crate::error::kind::ErrorKind::Gone => ("rejected", "grant_expired"),
        crate::error::kind::ErrorKind::Validation => ("rejected", "invalid_grant"),
        crate::error::kind::ErrorKind::NotFound => ("rejected", "not_found"),
        crate::error::kind::ErrorKind::RateLimit => ("rejected", "rate_limited"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_assertion(payload: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
        format!("{header}.{payload}.")
    }

    #[test]
    fn resolve_client_id_uses_request_client_id_first() {
        let assertion = unsigned_assertion(serde_json::json!({"sub": "assertion-client"}));

        let client_id = resolve_client_id(
            Some("request-client".to_owned()),
            Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer),
            Some(&assertion),
        )
        .unwrap();

        assert_eq!(client_id, "request-client");
    }

    #[test]
    fn resolve_client_id_extracts_jwt_bearer_assertion_subject() {
        let assertion = unsigned_assertion(serde_json::json!({
            "iss": "assertion-client",
            "sub": "assertion-client"
        }));

        let client_id = resolve_client_id(
            None,
            Some(identity_domain::openid_connect::ClientAssertionType::JwtBearer),
            Some(&assertion),
        )
        .unwrap();

        assert_eq!(client_id, "assertion-client");
    }
}
