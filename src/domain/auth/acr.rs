//! Authentication context classes (OpenID Connect `acr`).
//!
//! Every class this instance establishes, advertises and accepts is a variant
//! of [`AuthenticationContextClass`]; the protocol strings exist only here.
//! `phr` is the provider-neutral name registered in the IANA "Level of
//! Assurance (LoA) Profiles" registry (RFC 6711). `aal1` and `aal2` are this
//! instance's own values; registered federation profiles are not used because
//! they carry that federation's policy obligations.

use std::{fmt, str::FromStr};

/// Authentication context class established by an authentication event.
///
/// Variants are ordered from weakest to strongest, and a stronger class
/// satisfies every weaker one. That nesting holds for the methods this
/// instance offers: a phishing-resistant authentication is a user-verified
/// passkey, which is itself multi-factor.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AuthenticationContextClass {
    /// `aal1`: one factor, a password.
    #[serde(rename = "aal1")]
    SingleFactor,
    /// `aal2`: two distinct factors, a password followed by a one-time or
    /// recovery code, or a user-verified passkey.
    #[serde(rename = "aal2")]
    MultiFactor,
    /// OpenID EAP ACR Values `phr` (registered in the IANA LoA registry): a
    /// user-verified passkey, which a party controlled by the relying party
    /// cannot replay to this provider.
    #[serde(rename = "phr")]
    PhishingResistant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unsupported authentication context class")]
pub struct UnsupportedAuthenticationContextClass;

impl AuthenticationContextClass {
    /// All classes, weakest first; also the discovery order.
    pub const ALL: [Self; 3] = [
        Self::SingleFactor,
        Self::MultiFactor,
        Self::PhishingResistant,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleFactor => "aal1",
            Self::MultiFactor => "aal2",
            Self::PhishingResistant => "phr",
        }
    }

    /// Whether this established class meets a requirement for `requested`.
    #[must_use]
    pub fn satisfies(self, requested: Self) -> bool {
        self >= requested
    }

    /// Whether the class depends on a second factor. Such a class lapses back
    /// to [`Self::SingleFactor`] after the elevated authentication window.
    #[must_use]
    pub const fn is_multi_factor(self) -> bool {
        !matches!(self, Self::SingleFactor)
    }

    /// Parse a requested list (`acr_values`, `default_acr_values`, an
    /// essential `acr` claim), keeping order and dropping values this
    /// instance does not define; such a value can never be established.
    #[must_use]
    pub fn parse_list<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<Self> {
        let mut classes = Vec::new();
        for class in values.into_iter().filter_map(|value| value.parse().ok()) {
            if !classes.contains(&class) {
                classes.push(class);
            }
        }
        classes
    }
}

impl fmt::Display for AuthenticationContextClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for AuthenticationContextClass {
    type Err = UnsupportedAuthenticationContextClass;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|class| class.as_str() == value)
            .ok_or(UnsupportedAuthenticationContextClass)
    }
}

/// Whether an established context meets a request that accepts any of
/// `requested` (OpenID Connect `acr_values`; RFC 9470 §3 "requires one of
/// these values").
#[must_use]
pub fn acr_satisfies_any(
    established: Option<AuthenticationContextClass>,
    requested: &[AuthenticationContextClass],
) -> bool {
    established.is_some_and(|established| {
        requested
            .iter()
            .any(|&requested| established.satisfies(requested))
    })
}

/// The class a new authentication must establish for a request that accepts
/// any of `requested`: the weakest one listed, because every stronger class
/// satisfies it. Order expresses preference, never a stricter requirement.
#[must_use]
pub fn required_acr(
    requested: &[AuthenticationContextClass],
) -> Option<AuthenticationContextClass> {
    requested.iter().copied().min()
}

/// The `acr` reported to the client: the most preferred requested class the
/// authentication satisfies, so a relying party that checks the value against
/// its own list (RFC 9470 §4, OpenID Connect Core §5.5.1.1) recognizes it.
/// Without a satisfiable request the established class is reported.
#[must_use]
pub fn reported_acr(
    established: Option<AuthenticationContextClass>,
    requested: &[AuthenticationContextClass],
) -> Option<AuthenticationContextClass> {
    let established = established?;
    requested
        .iter()
        .copied()
        .find(|&requested| established.satisfies(requested))
        .or(Some(established))
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticationContextClass::{self, MultiFactor, PhishingResistant, SingleFactor},
        acr_satisfies_any, reported_acr, required_acr,
    };

    #[test]
    fn protocol_values_round_trip() {
        for class in AuthenticationContextClass::ALL {
            assert_eq!(class.as_str().parse(), Ok(class));
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::json!(class.as_str())
            );
        }
        assert!("aal3".parse::<AuthenticationContextClass>().is_err());
    }

    #[test]
    fn stronger_classes_satisfy_weaker_requirements_only() {
        assert!(PhishingResistant.satisfies(MultiFactor));
        assert!(MultiFactor.satisfies(SingleFactor));
        assert!(!MultiFactor.satisfies(PhishingResistant));
        assert!(!SingleFactor.satisfies(MultiFactor));
    }

    #[test]
    fn unknown_requested_values_are_dropped_in_order() {
        assert_eq!(
            AuthenticationContextClass::parse_list(["phr", "urn:example:unknown", "aal2", "phr",]),
            vec![PhishingResistant, MultiFactor]
        );
    }

    /// A new login and an existing session judge the same request alike:
    /// whatever a fresh login must reach is exactly enough for a session.
    #[test]
    fn new_and_existing_authentication_agree_for_every_request() {
        let classes = AuthenticationContextClass::ALL;
        let mut requests: Vec<Vec<AuthenticationContextClass>> = Vec::new();
        for first in classes {
            requests.push(vec![first]);
            for second in classes.into_iter().filter(|second| *second != first) {
                requests.push(vec![first, second]);
            }
        }
        for requested in &requests {
            let required = required_acr(requested).unwrap();
            for established in classes {
                assert_eq!(
                    acr_satisfies_any(Some(established), requested),
                    established.satisfies(required),
                    "{requested:?} with {established:?}"
                );
            }
        }
        assert!(!acr_satisfies_any(None, &[SingleFactor]));
    }

    #[test]
    fn the_reported_class_is_the_most_preferred_one_met() {
        assert_eq!(
            reported_acr(Some(PhishingResistant), &[MultiFactor]),
            Some(MultiFactor)
        );
        assert_eq!(
            reported_acr(Some(PhishingResistant), &[PhishingResistant, MultiFactor]),
            Some(PhishingResistant)
        );
        assert_eq!(
            reported_acr(Some(MultiFactor), &[PhishingResistant, MultiFactor]),
            Some(MultiFactor)
        );
        assert_eq!(reported_acr(Some(SingleFactor), &[]), Some(SingleFactor));
        assert_eq!(reported_acr(None, &[SingleFactor]), None);
    }
}
