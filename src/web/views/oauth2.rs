use serde::{Deserialize, Serialize};

use crate::domain::openid_connect::ScopeSet;

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
    pub redirect_uri: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizeErrorPageData {
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
    use crate::domain::openid_connect::ScopeSet;

    #[test]
    fn build_scope_display_marks_openid_as_essential() {
        let scopes = build_scope_display(&ScopeSet::parse("openid profile").unwrap());

        assert_eq!(scopes[0].name, "openid");
        assert!(scopes[0].essential);
        assert_eq!(scopes[1].name, "profile");
    }

    #[test]
    fn consent_decision_deserializes_from_json() {
        let decision: ConsentDecision = serde_json::from_str("\"approve\"").unwrap();
        assert!(matches!(decision, ConsentDecision::Approve));
    }
}
