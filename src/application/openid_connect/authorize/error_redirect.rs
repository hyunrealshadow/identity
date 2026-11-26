use identity_domain::openid_connect::{ScopeSet, identifier::parse_client_id};
use url::Url;

use super::AuthorizeService;

impl AuthorizeService {
    /// Where an authorization error may be returned to the client.
    ///
    /// The requested `redirect_uri` is used only when it is registered for the
    /// client. A request without one may fall back to the client's only
    /// registered URI unless it is an OpenID Connect request, which must name
    /// it. `None` means the error is shown to the user instead, so an
    /// unverified URI never receives it.
    pub async fn error_redirect_uri(
        &self,
        client_id: Option<&str>,
        redirect_uri: Option<&str>,
        scope: Option<&str>,
    ) -> Option<Url> {
        let client_oid = client_id.and_then(|id| parse_client_id(id).ok())?;
        let client = self
            .client_repo
            .find_by_oid(client_oid)
            .await
            .ok()
            .flatten()?;
        let target = match redirect_uri.filter(|uri| !uri.is_empty()) {
            Some(uri) => client.has_redirect_uri_str(uri).then_some(uri)?,
            None => {
                let openid = scope.is_some_and(|scope| {
                    ScopeSet::parse(scope).is_ok_and(|scope| scope.contains_openid())
                });
                (!openid).then(|| client.single_redirect_uri()).flatten()?
            }
        };
        Url::parse(target).ok()
    }
}
