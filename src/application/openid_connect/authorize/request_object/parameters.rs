//! Request Object claim validation, precedence, and authorization parameter merging.

use super::super::AuthorizationRequestParams;
use super::super::AuthorizeService;
use crate::error::codes::common::CommonErrorCode;
use crate::error::{AppError, codes::authorize::AuthorizeErrorCode};
use chrono::Utc;
use identity_domain::openid_connect::{
    ClaimRequestMap,
    model::{authorization_request::ClaimsRequest, claim::JwtClaimNames},
};
use serde_json::{Value, from_str};
use url::Url;

impl AuthorizeService {
    pub(in super::super) fn merge_request_object_params(
        mut params: AuthorizationRequestParams,
        payload: &Value,
    ) -> Result<AuthorizationRequestParams, AppError> {
        if let Some(value) = payload
            .get("response_type")
            .and_then(|value| value.as_str())
        {
            params.response_type = value.to_string();
        }
        if let Some(value) = payload
            .get("response_mode")
            .and_then(|value| value.as_str())
        {
            params.response_mode = Some(value.to_string());
        }
        if let Some(value) = payload.get("client_id").and_then(|value| value.as_str()) {
            params.client_id = value.to_string();
        }
        if let Some(value) = payload.get("redirect_uri").and_then(|value| value.as_str()) {
            params.redirect_uri = value.to_string();
        }
        if let Some(value) = payload.get("scope").and_then(|value| value.as_str()) {
            params.scope = value.to_string();
        }
        if let Some(value) = payload.get("resource") {
            params.resources = match value {
                Value::String(uri) => vec![uri.clone()],
                Value::Array(values) if !values.is_empty() => values
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| AppError::from_code(CommonErrorCode::InvalidTarget))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                _ => {
                    return Err(AppError::from_code(CommonErrorCode::InvalidTarget));
                }
            };
        }
        if let Some(value) = payload.get("state").and_then(|value| value.as_str()) {
            params.state = value.to_string();
        }
        if let Some(value) = payload.get("nonce").and_then(|value| value.as_str()) {
            params.nonce = Some(value.to_string());
        }
        if let Some(value) = payload.get("login_hint").and_then(|value| value.as_str()) {
            params.login_hint = Some(value.to_string());
        }
        if let Some(value) = payload.get("display").and_then(|value| value.as_str()) {
            params.display = Some(value.to_string());
        }
        if let Some(value) = payload.get("prompt").and_then(|value| value.as_str()) {
            params.prompt = Some(value.to_string());
        }
        if let Some(value) = payload.get("max_age")
            && let Some(value) = value.as_i64()
        {
            params.max_age = Some(value.to_string());
        }
        if let Some(value) = payload.get("ui_locales").and_then(|value| value.as_str()) {
            params.ui_locales = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("claims_locales")
            .and_then(|value| value.as_str())
        {
            params.claims_locales = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("id_token_hint")
            .and_then(|value| value.as_str())
        {
            params.id_token_hint = Some(value.to_string());
        }
        if let Some(value) = payload.get("acr_values").and_then(|value| value.as_str()) {
            params.acr_values = Some(value.to_string());
        }
        if let Some(value) = payload.get("claims") {
            params.claims = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("code_challenge")
            .and_then(|value| value.as_str())
        {
            params.code_challenge = Some(value.to_string());
        }
        if let Some(value) = payload
            .get("code_challenge_method")
            .and_then(|value| value.as_str())
        {
            params.code_challenge_method = Some(value.to_string());
        }

        Ok(params)
    }

    pub(in super::super) fn validate_request_object_claims(
        params: &AuthorizationRequestParams,
        payload: &Value,
        issuer: &Url,
    ) -> Result<(), AppError> {
        Self::validate_required_request_object_field(
            payload,
            "response_type",
            params.response_type.as_str(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "response_mode",
            params.response_mode.as_deref(),
        )?;
        Self::validate_required_request_object_field(
            payload,
            "client_id",
            params.client_id.as_str(),
        )?;
        // Per OIDCC-6.1, request object values supersede query parameters.
        // For redirect_uri, we do NOT reject mismatches — the request object's
        // redirect_uri will override the query param during merge.
        // This allows the request object to specify the authoritative redirect_uri.
        Self::validate_required_request_object_field(payload, "scope", params.scope.as_str())?;
        Self::validate_required_request_object_field(payload, "state", params.state.as_str())?;
        Self::validate_optional_request_object_field(payload, "nonce", params.nonce.as_deref())?;
        Self::validate_optional_request_object_field(
            payload,
            "display",
            params.display.as_deref(),
        )?;
        Self::validate_optional_request_object_field(payload, "prompt", params.prompt.as_deref())?;
        Self::validate_optional_numeric_request_object_field(
            payload,
            "max_age",
            params.max_age.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "ui_locales",
            params.ui_locales.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "claims_locales",
            params.claims_locales.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "id_token_hint",
            params.id_token_hint.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "login_hint",
            params.login_hint.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "acr_values",
            params.acr_values.as_deref(),
        )?;
        Self::validate_optional_json_request_object_field(
            payload,
            "claims",
            params.claims.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "code_challenge",
            params.code_challenge.as_deref(),
        )?;
        Self::validate_optional_request_object_field(
            payload,
            "code_challenge_method",
            params.code_challenge_method.as_deref(),
        )?;

        if let Some(iss) = payload
            .get(JwtClaimNames::ISS)
            .and_then(|value| value.as_str())
            && iss != params.client_id
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectIssMismatch,
            ));
        }

        if let Some(aud) = payload.get(JwtClaimNames::AUD) {
            let issuer_value = issuer.as_str();
            let matches = aud
                .as_str()
                .map(|value| value == issuer_value)
                .unwrap_or_else(|| {
                    aud.as_array()
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|value| value.as_str())
                                .any(|value| value == issuer_value)
                        })
                        .unwrap_or(false)
                });

            if !matches {
                return Err(AppError::from_code(
                    AuthorizeErrorCode::RequestObjectAudMismatch,
                ));
            }
        }

        let now = Utc::now().timestamp();
        if let Some(exp) = payload
            .get(JwtClaimNames::EXP)
            .and_then(|value| value.as_i64())
            && exp <= now
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectExpired,
            ));
        }

        if let Some(nbf) = payload
            .get(JwtClaimNames::NBF)
            .and_then(|value| value.as_i64())
            && nbf > now
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectNotYetValid,
            ));
        }

        if let Some(iat) = payload
            .get(JwtClaimNames::IAT)
            .and_then(|value| value.as_i64())
            && iat > now
        {
            return Err(AppError::from_code(
                AuthorizeErrorCode::RequestObjectIatFuture,
            ));
        }

        Ok(())
    }

    fn validate_required_request_object_field(
        payload: &Value,
        field: &str,
        outer: &str,
    ) -> Result<(), AppError> {
        if outer.trim().is_empty() {
            return Ok(());
        }

        if let Some(inner) = payload.get(field).and_then(|value| value.as_str())
            && inner != outer
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                    .with_param("field", field),
            );
        }

        Ok(())
    }

    fn validate_optional_request_object_field(
        payload: &Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) =
            (payload.get(field).and_then(|value| value.as_str()), outer)
            && inner != outer
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                    .with_param("field", field),
            );
        }

        Ok(())
    }

    fn validate_optional_numeric_request_object_field(
        payload: &Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) =
            (payload.get(field).and_then(|value| value.as_i64()), outer)
            && inner.to_string() != outer
        {
            return Err(
                AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                    .with_param("field", field),
            );
        }

        Ok(())
    }

    fn validate_optional_json_request_object_field(
        payload: &Value,
        field: &str,
        outer: Option<&str>,
    ) -> Result<(), AppError> {
        if let (Some(inner), Some(outer)) = (payload.get(field), outer) {
            let outer = from_str::<Value>(outer).map_err(AppError::map_source(
                AuthorizeErrorCode::RequestObjectJsonInvalid,
            ))?;

            if inner != &outer {
                return Err(
                    AppError::from_code(AuthorizeErrorCode::RequestObjectFieldMismatch)
                        .with_param("field", field),
                );
            }
        }

        Ok(())
    }

    pub(in super::super) fn parse_claims_request(raw: &str) -> Result<ClaimsRequest, AppError> {
        let value = from_str::<Value>(raw)
            .map_err(AppError::map_source(AuthorizeErrorCode::ClaimsParamInvalid))?;
        let object = value
            .as_object()
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClaimsNotObject))?;

        // A `null` value (e.g. from a serialized `Option::None`) is treated as
        // absent. Without this, a claims document produced by serializing
        // `ClaimsRequest` — which emits `"id_token": null` when that section is
        // unset — would be rejected on re-parse as "field not an object".
        let map_field = |field: &str| -> Result<Option<ClaimRequestMap>, AppError> {
            match object.get(field) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => value
                    .as_object()
                    .cloned()
                    .map(ClaimRequestMap::from_json_map)
                    .map(Some)
                    .ok_or_else(|| {
                        AppError::from_code(AuthorizeErrorCode::ClaimsFieldNotObject)
                            .with_param("field", field)
                    }),
            }
        };

        Ok(ClaimsRequest {
            id_token: map_field("id_token")?,
            userinfo: map_field("userinfo")?,
        })
    }
}
