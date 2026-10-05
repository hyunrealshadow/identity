use identity_application::openid_connect::device::DeviceVerificationStatus;
use identity_domain::openid_connect::model::claim::StandardScopes;
use identity_domain::openid_connect::scope_catalog::ScopeDescription;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use identity_domain::openid_connect::ScopeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeDisplay {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub descriptions: BTreeMap<String, String>,
    pub essential: bool,
    pub previously_granted: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsentPageData {
    pub login_id: String,
    pub client_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub scopes: Vec<ScopeDisplay>,
    pub csrf_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales: Option<Vec<String>>,
}

/// Consent decisions for both flows identify the bound login interaction.
#[derive(Debug, Clone, Deserialize)]
pub struct ConsentDecisionPayload {
    #[serde(default)]
    pub login_id: Option<String>,
    #[serde(default)]
    pub user_code: Option<String>,
    pub decision: ConsentDecision,
}

/// Account a device decision is attributed to, so the verification page can
/// show who is approving instead of leaving it implicit.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceConsentAccount {
    pub name: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// Device verification page data for a session-bound login interaction.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceConsentPageData {
    pub login_id: String,
    pub user_code: String,
    pub status: DeviceVerificationStatus,
    pub consent_required: bool,
    pub client_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    pub client_uri: Option<String>,
    pub scopes: Vec<ScopeDisplay>,
    pub csrf_token: String,
    /// Session behind the browser that is answering: the account the decision
    /// is recorded against.
    pub account: DeviceConsentAccount,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsentApiResponse {
    pub status: &'static str,
    pub continue_uri: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormPostField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FormPostPageData {
    pub title: String,
    pub message: String,
    pub action: String,
    pub fields: Vec<FormPostField>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FrontChannelNotificationView {
    pub logout_uri: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LogoutPageData {
    pub title: String,
    pub frontchannel_notifications: Vec<FrontChannelNotificationView>,
    pub post_logout_redirect_uri: Option<String>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckSessionPageData {
    pub op_browser_state_json: String,
    pub lang: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorPageData {
    pub status_code: u16,
    pub oauth_error_code: Option<String>,
    pub error_code: Option<u32>,
    pub title: String,
    pub message: String,
    pub details: Vec<String>,
}

pub fn build_scope_display(
    scope: &ScopeSet,
    previously_granted: &[String],
    descriptions: &[ScopeDescription],
) -> Vec<ScopeDisplay> {
    scope
        .names()
        .into_iter()
        .map(|name| {
            let metadata = descriptions.iter().find(|entry| entry.name == name);
            ScopeDisplay {
                name: name.to_owned(),
                display_name: metadata
                    .map_or_else(|| name.to_owned(), |entry| entry.display_name.clone()),
                description: metadata.map_or_else(String::new, |entry| entry.description.clone()),
                descriptions: metadata
                    .map_or_else(Default::default, |entry| entry.descriptions.clone()),
                essential: name == StandardScopes::OPENID,
                previously_granted: previously_granted.iter().any(|granted| granted == name),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::build_scope_display;
    use identity_domain::openid_connect::ScopeSet;

    #[test]
    fn build_scope_display_marks_openid_as_essential() {
        let scopes = build_scope_display(&ScopeSet::parse("openid profile").unwrap(), &[], &[]);

        assert_eq!(scopes[0].name, "openid");
        assert!(scopes[0].essential);
        assert_eq!(scopes[1].name, "profile");
    }

    #[test]
    fn build_scope_display_includes_address_and_phone() {
        let scopes =
            build_scope_display(&ScopeSet::parse("openid address phone").unwrap(), &[], &[]);
        let names = scopes
            .iter()
            .map(|scope| scope.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(names, vec!["openid", "address", "phone"]);
    }

    #[test]
    fn scope_display_distinguishes_remembered_and_new_permissions() {
        let requested = ScopeSet::parse("openid profile email").unwrap();
        let scopes = build_scope_display(
            &requested,
            &["openid".into(), "email".into(), "phone".into()],
            &[],
        );
        let statuses = scopes
            .iter()
            .map(|scope| (scope.name.as_str(), scope.previously_granted))
            .collect::<Vec<_>>();
        assert_eq!(
            statuses,
            vec![("openid", true), ("profile", false), ("email", true)]
        );
    }

    #[test]
    fn scope_display_does_not_assume_essential_permissions_were_approved() {
        let requested = ScopeSet::parse("openid profile").unwrap();
        assert!(
            build_scope_display(&requested, &[], &[])
                .iter()
                .all(|scope| !scope.previously_granted)
        );
        assert!(
            build_scope_display(&requested, &["openid".into(), "profile".into()], &[])
                .iter()
                .all(|scope| scope.previously_granted)
        );
    }
}
