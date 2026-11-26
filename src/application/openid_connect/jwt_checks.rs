use josekit::jwt::JwtPayload;
use serde_json::Value;

use crate::domain::openid_connect::model::claim::JwtClaimNames;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtTimeValidationError {
    ExpMissing,
    Expired,
    NotYetValid,
    IssuedInFuture,
}

pub fn audience_matches(payload: &JwtPayload, valid_audiences: &[&str]) -> bool {
    payload
        .claim(JwtClaimNames::AUD)
        .is_some_and(|value| audience_value_matches(value, valid_audiences))
}

pub fn audience_value_matches(value: &Value, valid_audiences: &[&str]) -> bool {
    value
        .as_str()
        .map(|aud| valid_audiences.contains(&aud))
        .or_else(|| {
            value.as_array().map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .any(|aud| valid_audiences.contains(&aud))
            })
        })
        .unwrap_or(false)
}

pub fn validate_required_exp_and_optional_window(
    payload: &JwtPayload,
    now: i64,
) -> Result<(), JwtTimeValidationError> {
    let exp = payload
        .claim(JwtClaimNames::EXP)
        .and_then(numeric_date)
        .ok_or(JwtTimeValidationError::ExpMissing)?;
    if exp <= now {
        return Err(JwtTimeValidationError::Expired);
    }

    validate_optional_time_window(payload, now)
}

pub fn validate_optional_time_window(
    payload: &JwtPayload,
    now: i64,
) -> Result<(), JwtTimeValidationError> {
    if let Some(nbf) = payload.claim(JwtClaimNames::NBF).and_then(numeric_date)
        && nbf > now
    {
        return Err(JwtTimeValidationError::NotYetValid);
    }

    if let Some(iat) = payload.claim(JwtClaimNames::IAT).and_then(numeric_date)
        && iat > now
    {
        return Err(JwtTimeValidationError::IssuedInFuture);
    }

    Ok(())
}

pub fn json_audience_matches(value: &Value, valid_audiences: &[&str]) -> bool {
    audience_value_matches(value, valid_audiences)
}

fn numeric_date(value: &Value) -> Option<i64> {
    if let Some(value) = value.as_i64() {
        return Some(value);
    }
    if let Some(value) = value.as_u64() {
        return i64::try_from(value).ok();
    }
    let value = value.as_f64()?;
    // 2^63 == 9_223_372_036_854_775_808.0; finite values in [-2^63, 2^63) fit in i64.
    if !value.is_finite()
        || value < -9_223_372_036_854_775_808.0
        || value >= 9_223_372_036_854_775_808.0
    {
        return None;
    }
    Some(value.trunc() as i64)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use josekit::jwt::JwtPayload;
    use serde_json::json;

    use super::{
        JwtTimeValidationError, audience_value_matches, validate_required_exp_and_optional_window,
    };
    use crate::domain::openid_connect::model::claim::JwtClaimNames;

    #[test]
    fn audience_value_matches_string_or_array() {
        assert!(audience_value_matches(
            &json!("https://identity.example.com"),
            &["https://identity.example.com"]
        ));
        assert!(audience_value_matches(
            &json!(["other", "https://identity.example.com"]),
            &["https://identity.example.com"]
        ));
        assert!(!audience_value_matches(
            &json!(["other"]),
            &["https://identity.example.com"]
        ));
    }

    #[test]
    fn required_exp_rejects_missing_or_expired_assertions() {
        let mut payload = JwtPayload::new();
        assert_eq!(
            validate_required_exp_and_optional_window(&payload, 100),
            Err(JwtTimeValidationError::ExpMissing)
        );

        payload
            .set_claim(JwtClaimNames::EXP, Some(json!(100)))
            .unwrap();
        assert_eq!(
            validate_required_exp_and_optional_window(&payload, 100),
            Err(JwtTimeValidationError::Expired)
        );
    }

    #[test]
    fn required_exp_accepts_future_exp_with_valid_window() {
        let mut payload = JwtPayload::new();
        payload
            .set_claim(JwtClaimNames::EXP, Some(json!(101)))
            .unwrap();

        assert_eq!(
            validate_required_exp_and_optional_window(&payload, 100),
            Ok(())
        );
    }

    #[test]
    fn required_exp_accepts_josekit_numeric_date() {
        let mut payload = JwtPayload::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        payload.set_expires_at(&(now + Duration::from_secs(1)));

        assert_eq!(
            validate_required_exp_and_optional_window(&payload, 100),
            Ok(())
        );
    }

    #[test]
    fn numeric_date_rejects_overflowing_values_and_accepts_fractional_dates() {
        let mut payload = JwtPayload::new();
        payload
            .set_claim(JwtClaimNames::EXP, Some(json!(1e30)))
            .unwrap();
        assert_eq!(
            validate_required_exp_and_optional_window(&payload, 100),
            Err(JwtTimeValidationError::ExpMissing)
        );

        payload
            .set_claim(JwtClaimNames::EXP, Some(json!(u64::MAX)))
            .unwrap();
        assert_eq!(
            validate_required_exp_and_optional_window(&payload, 100),
            Err(JwtTimeValidationError::ExpMissing)
        );

        payload
            .set_claim(JwtClaimNames::EXP, Some(json!(101.5)))
            .unwrap();
        assert_eq!(
            validate_required_exp_and_optional_window(&payload, 100),
            Ok(())
        );
    }
}
