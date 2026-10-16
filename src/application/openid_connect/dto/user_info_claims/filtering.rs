//! Scope and essential-claim filtering for UserInfo and ID Tokens.

use identity_domain::openid_connect::{
    ClaimsRequest, ClaimsRequestSection, ScopeSet, model::claim::JwtClaimNames,
};

use super::UserInfoClaims;

impl UserInfoClaims {
    pub fn apply_scope_filter(&mut self, scope: &ScopeSet, claims_request: Option<&ClaimsRequest>) {
        self.apply_scope_filter_for_claim_sections(
            scope,
            claims_request,
            &[ClaimsRequestSection::UserInfo],
        );
    }

    pub fn apply_scope_filter_for_id_token(
        &mut self,
        scope: &ScopeSet,
        claims_request: Option<&ClaimsRequest>,
    ) {
        self.apply_scope_filter_for_claim_sections(
            scope,
            claims_request,
            &[ClaimsRequestSection::IdToken],
        );
    }

    fn apply_scope_filter_for_claim_sections(
        &mut self,
        scope: &ScopeSet,
        claims_request: Option<&ClaimsRequest>,
        claim_sections: &[ClaimsRequestSection],
    ) {
        let essential_claims = Self::extract_essential_claims(claims_request, claim_sections);

        if !scope.profile && !essential_claims.contains(&JwtClaimNames::NAME) {
            self.name = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::GIVEN_NAME) {
            self.given_name = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::FAMILY_NAME) {
            self.family_name = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::MIDDLE_NAME) {
            self.middle_name = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::NICKNAME) {
            self.nickname = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::PROFILE) {
            self.profile = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::PICTURE) {
            self.picture = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::WEBSITE) {
            self.website = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::GENDER) {
            self.gender = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::BIRTHDATE) {
            self.birthdate = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::ZONEINFO) {
            self.zoneinfo = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::LOCALE) {
            self.locale = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::PREFERRED_USERNAME) {
            self.preferred_username = None;
        }
        if !scope.profile && !essential_claims.contains(&JwtClaimNames::UPDATED_AT) {
            self.updated_at = None;
        }

        if !scope.email && !essential_claims.contains(&JwtClaimNames::EMAIL) {
            self.email = None;
            self.email_verified = None;
        }

        if !scope.phone && !essential_claims.contains(&JwtClaimNames::PHONE_NUMBER) {
            self.phone_number = None;
            self.phone_number_verified = None;
        }

        if !scope.address && !essential_claims.contains(&JwtClaimNames::ADDRESS) {
            self.address = None;
        }
    }

    fn extract_essential_claims(
        claims_request: Option<&ClaimsRequest>,
        claim_sections: &[ClaimsRequestSection],
    ) -> Vec<&'static str> {
        let Some(claims_request) = claims_request else {
            return Vec::new();
        };

        claims_request
            .essential_claim_names(claim_sections)
            .into_iter()
            .filter_map(known_claim_name)
            .collect()
    }
}

fn known_claim_name(name: &str) -> Option<&'static str> {
    match name {
        n if n == JwtClaimNames::NAME => Some(JwtClaimNames::NAME),
        n if n == JwtClaimNames::GIVEN_NAME => Some(JwtClaimNames::GIVEN_NAME),
        n if n == JwtClaimNames::FAMILY_NAME => Some(JwtClaimNames::FAMILY_NAME),
        n if n == JwtClaimNames::MIDDLE_NAME => Some(JwtClaimNames::MIDDLE_NAME),
        n if n == JwtClaimNames::NICKNAME => Some(JwtClaimNames::NICKNAME),
        n if n == JwtClaimNames::PROFILE => Some(JwtClaimNames::PROFILE),
        n if n == JwtClaimNames::PICTURE => Some(JwtClaimNames::PICTURE),
        n if n == JwtClaimNames::WEBSITE => Some(JwtClaimNames::WEBSITE),
        n if n == JwtClaimNames::GENDER => Some(JwtClaimNames::GENDER),
        n if n == JwtClaimNames::BIRTHDATE => Some(JwtClaimNames::BIRTHDATE),
        n if n == JwtClaimNames::ZONEINFO => Some(JwtClaimNames::ZONEINFO),
        n if n == JwtClaimNames::LOCALE => Some(JwtClaimNames::LOCALE),
        n if n == JwtClaimNames::PREFERRED_USERNAME => Some(JwtClaimNames::PREFERRED_USERNAME),
        n if n == JwtClaimNames::EMAIL => Some(JwtClaimNames::EMAIL),
        n if n == JwtClaimNames::PHONE_NUMBER => Some(JwtClaimNames::PHONE_NUMBER),
        n if n == JwtClaimNames::ADDRESS => Some(JwtClaimNames::ADDRESS),
        n if n == JwtClaimNames::UPDATED_AT => Some(JwtClaimNames::UPDATED_AT),
        _ => None,
    }
}
