use serde::{Deserialize, Serialize};

use identity_domain::openid_connect::ScopeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentDecision {
    Approve,
    Deny,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeDisplay {
    pub name: &'static str,
    pub description: &'static str,
    pub essential: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsentPageData {
    pub login_id: String,
    pub client_name: String,
    pub client_uri: Option<String>,
    pub scopes: Vec<ScopeDisplay>,
    pub csrf_token: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsentDecisionForm {
    pub login_id: String,
    pub decision: ConsentDecision,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsentDecisionPayload {
    pub login_id: String,
    pub decision: ConsentDecision,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConsentApiResponse {
    pub status: &'static str,
    pub continue_uri: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizeErrorPageData {
    pub title: String,
    pub message: String,
    pub details: Vec<String>,
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
    pub op_browser_state: String,
    pub lang: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorPageData {
    pub status_code: u16,
    pub title: String,
    pub message: String,
    pub details: Vec<String>,
}

pub fn build_scope_display(scope: &ScopeSet) -> Vec<ScopeDisplay> {
    let mut scopes = Vec::new();

    if scope.openid {
        scopes.push(ScopeDisplay {
            name: "openid",
            description: "Access your account identifier",
            essential: true,
        });
    }
    if scope.profile {
        scopes.push(ScopeDisplay {
            name: "profile",
            description: "Read your basic profile information",
            essential: false,
        });
    }
    if scope.email {
        scopes.push(ScopeDisplay {
            name: "email",
            description: "Read your email address",
            essential: false,
        });
    }
    if scope.address {
        scopes.push(ScopeDisplay {
            name: "address",
            description: "Read your postal address",
            essential: false,
        });
    }
    if scope.phone {
        scopes.push(ScopeDisplay {
            name: "phone",
            description: "Read your phone number",
            essential: false,
        });
    }
    if scope.offline_access {
        scopes.push(ScopeDisplay {
            name: "offline_access",
            description: "Request refresh tokens for long-lived access",
            essential: false,
        });
    }

    scopes
}

#[cfg(test)]
mod tests {
    use super::{ConsentDecision, build_scope_display};
    use identity_domain::openid_connect::ScopeSet;

    #[test]
    fn build_scope_display_marks_openid_as_essential() {
        let scopes = build_scope_display(&ScopeSet::parse("openid profile").unwrap());

        assert_eq!(scopes[0].name, "openid");
        assert!(scopes[0].essential);
        assert_eq!(scopes[1].name, "profile");
    }

    #[test]
    fn build_scope_display_includes_address_and_phone() {
        let scopes = build_scope_display(&ScopeSet::parse("openid address phone").unwrap());
        let names = scopes.iter().map(|scope| scope.name).collect::<Vec<_>>();

        assert_eq!(names, vec!["openid", "address", "phone"]);
        assert_eq!(scopes[1].description, "Read your postal address");
        assert_eq!(scopes[2].description, "Read your phone number");
    }

    #[test]
    fn consent_decision_deserializes_from_json() {
        let decision: ConsentDecision = serde_json::from_str("\"approve\"").unwrap();
        assert!(matches!(decision, ConsentDecision::Approve));
    }
}
