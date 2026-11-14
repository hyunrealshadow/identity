use serde::Serialize;

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
