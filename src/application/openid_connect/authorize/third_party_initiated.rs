use super::*;

#[derive(Debug, Clone)]
pub struct ThirdPartyInitiatedLoginRequest {
    pub client_id: String,
    pub login_hint: Option<String>,
    pub target_link_uri: Option<Url>,
}

impl AuthorizeService {
    pub async fn third_party_initiated_login(
        &self,
        request: ThirdPartyInitiatedLoginRequest,
    ) -> Result<Url, AppError> {
        let client_id = Uuid::parse_str(request.client_id.trim()).map_err(|error| {
            AppError::from_code(AuthorizeErrorCode::ClientIdInvalid).with_source(error)
        })?;

        let client = self
            .client_repo
            .find_by_oid(client_id)
            .await
            .map_err(|error| {
                AppError::from_code(AuthorizeErrorCode::ClientLookupFailed).with_source(error)
            })?
            .ok_or_else(|| AppError::from_code(AuthorizeErrorCode::ClientNotFound))?;

        let mut redirect_uri = client
            .metadata()
            .initiate_login_uri
            .clone()
            .ok_or_else(|| {
                AppError::from_code(AuthorizeErrorCode::InitiateLoginUriNotRegistered)
            })?;
        let issuer = self.provider_service.issuer()?;

        {
            let mut query = redirect_uri.query_pairs_mut();
            query.append_pair("iss", issuer.as_str());
            query.append_pair("client_id", client.client().oid.to_string().as_str());
            if let Some(login_hint) = request.login_hint.as_deref() {
                query.append_pair("login_hint", login_hint);
            }
            if let Some(target_link_uri) = request.target_link_uri.as_ref() {
                query.append_pair("target_link_uri", target_link_uri.as_str());
            }
        }

        Ok(redirect_uri)
    }
}
