use identity_application::openid_connect::user_info::TokenClaims;
use identity_domain::user::User;
use identity_infrastructure::AppState;

pub struct RequestContext {
    pub state: AppState,
    pub claims: TokenClaims,
    pub user: User,
    pub locale: unic_langid::LanguageIdentifier,
    pub request_id: String,
}
