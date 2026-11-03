//! Trusted public-error inventory and direct, fallback-free Fluent validation.
use fluent_templates::{
    FluentBundle,
    fluent_bundle::{FluentArgs, FluentResource},
};
use identity_application::error::{
    code::AppErrorCode,
    codes::{
        account::AccountErrorCode, auth::AuthErrorCode,
        authorization::AUTHORIZATION_ERROR_INVENTORY, authorize::AuthorizeErrorCode,
        common::CommonErrorCode, device::DeviceAuthorizationErrorCode, graphql::GraphqlErrorCode,
        graphql_transport::GraphqlTransportErrorCode, group::GROUP_ERROR_INVENTORY,
        openid_connect::OpenIdConnectErrorCode, rbac::RBAC_ERROR_INVENTORY, token::TokenErrorCode,
        user_management::USER_MANAGEMENT_ERROR_INVENTORY,
    },
    kind::ErrorKind,
};
use std::{fs, path::Path};
use unic_langid::LanguageIdentifier;

use crate::web::tera as web_tera;

#[derive(Debug, Clone)]
pub struct PublicErrorDefinition {
    pub code: u32,
    pub kind: ErrorKind,
    pub fluent_key: String,
    pub usage_module: &'static str,
    pub required: &'static [&'static str],
    pub optional: &'static [&'static str],
}

/// This inventory comes from application contracts, never from a locale file.
/// Self-service scopes keep their existing error ranges. The separately typed
/// authorization inventory supplies management and business RBAC errors.
pub fn public_error_inventory() -> Vec<PublicErrorDefinition> {
    fn definitions<C: AppErrorCode + Copy + strum::IntoEnumIterator>(
        module: &'static str,
    ) -> Vec<PublicErrorDefinition> {
        C::iter()
            .map(|code| PublicErrorDefinition {
                code: code.code(),
                kind: code.kind(),
                fluent_key: format!("E{}", code.code()),
                usage_module: module,
                required: match code.code() {
                    23003 => &["response_type"],
                    23007 => &["display"],
                    23008 => &["prompt"],
                    23011 => &["code_challenge_method"],
                    23013 => &["fields"],
                    23025 => &["alg"],
                    23056 => &["scopes"],
                    23066 => &["response_mode"],
                    24000 => &["grant_type"],
                    24040 => &["alg"],
                    24048 => &["code_challenge_method"],
                    11006 => &["credential_type"],
                    11009 => &["session_id"],
                    11019 => &["limit"],
                    28002 => &["max"],
                    28005 => &["scope"],
                    _ => &[],
                },
                optional: &[],
            })
            .collect()
    }
    let mut inventory = definitions::<CommonErrorCode>("common");
    inventory.extend(definitions::<AuthErrorCode>("auth"));
    inventory.extend(definitions::<AccountErrorCode>("account"));
    inventory.extend(definitions::<AuthorizeErrorCode>(
        "openid_connect.authorize",
    ));
    inventory.extend(definitions::<DeviceAuthorizationErrorCode>(
        "openid_connect.device",
    ));
    inventory.extend(definitions::<TokenErrorCode>("openid_connect.token"));
    inventory.extend(definitions::<OpenIdConnectErrorCode>(
        "openid_connect.user_info",
    ));
    inventory.extend(definitions::<GraphqlErrorCode>("graphql"));
    inventory.extend(definitions::<GraphqlTransportErrorCode>(
        "graphql.transport",
    ));
    inventory.extend(AUTHORIZATION_ERROR_INVENTORY.iter().map(|definition| {
        PublicErrorDefinition {
            code: definition.numeric_code,
            kind: definition.kind,
            fluent_key: definition.fluent_key.to_owned(),
            usage_module: definition.usage_module,
            required: definition.required_params,
            optional: definition.optional_params,
        }
    }));
    inventory.extend(USER_MANAGEMENT_ERROR_INVENTORY.iter().map(|definition| {
        PublicErrorDefinition {
            code: definition.numeric_code,
            kind: definition.kind,
            fluent_key: definition.fluent_key.to_owned(),
            usage_module: definition.usage_module,
            required: definition.required_params,
            optional: definition.optional_params,
        }
    }));
    inventory.extend(
        RBAC_ERROR_INVENTORY
            .iter()
            .map(|definition| PublicErrorDefinition {
                code: definition.numeric_code,
                kind: definition.kind,
                fluent_key: definition.fluent_key.to_owned(),
                usage_module: definition.usage_module,
                required: definition.required_params,
                optional: definition.optional_params,
            }),
    );
    inventory.extend(
        GROUP_ERROR_INVENTORY
            .iter()
            .map(|definition| PublicErrorDefinition {
                code: definition.numeric_code,
                kind: definition.kind,
                fluent_key: definition.fluent_key.to_owned(),
                usage_module: definition.usage_module,
                required: definition.required_params,
                optional: definition.optional_params,
            }),
    );
    inventory
}

fn validate_sources(
    locale: &str,
    sources: &[String],
    inventory: &[PublicErrorDefinition],
) -> Result<(), String> {
    let language = locale
        .parse::<LanguageIdentifier>()
        .map_err(|_| "invalid catalog locale".to_owned())?;
    let mut bundle = FluentBundle::new_concurrent(vec![language]);
    web_tera::register_list_function(&mut bundle);
    bundle.set_use_isolating(false);
    for source in sources {
        let resource = FluentResource::try_new(source.clone())
            .map_err(|_| format!("{locale}: invalid Fluent syntax"))?;
        bundle
            .add_resource(resource)
            .map_err(|_| format!("{locale}: duplicate Fluent key"))?;
    }
    for definition in inventory {
        let key = &definition.fluent_key;
        let pattern = bundle
            .get_message(key)
            .and_then(|message| message.value())
            .ok_or_else(|| format!("{locale}: missing error message {key}"))?;
        let mut args = FluentArgs::new();
        for name in definition.required.iter().chain(definition.optional) {
            args.set(*name, "sample");
        }
        let mut errors = Vec::new();
        let rendered = bundle.format_pattern(pattern, Some(&args), &mut errors);
        if !errors.is_empty() || rendered.trim().is_empty() || rendered == key.as_str() {
            return Err(format!(
                "{locale}: {key} has an invalid message or undeclared parameters"
            ));
        }
        // Omitting each declared required parameter must be detected by the
        // real Fluent formatter, rather than a string/regex approximation.
        for missing in definition.required {
            let mut incomplete = FluentArgs::new();
            for name in definition
                .required
                .iter()
                .chain(definition.optional)
                .filter(|name| *name != missing)
            {
                incomplete.set(*name, "sample");
            }
            let mut missing_errors = Vec::new();
            let _ = bundle.format_pattern(pattern, Some(&incomplete), &mut missing_errors);
            if missing_errors.is_empty() {
                return Err(format!(
                    "{locale}: {key} does not use required parameter {missing}"
                ));
            }
        }
    }
    Ok(())
}

/// Validate each locale independently. No ArcLoader fallback participates.
pub fn validate_error_catalogs(root: &Path) -> Result<(), String> {
    let inventory = public_error_inventory();
    for locale in ["en-US", "zh-CN"] {
        let locale_root = root.join(locale);
        let mut files = fs::read_dir(&locale_root)
            .map_err(|_| format!("{locale}: locale catalog directory is missing"))?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| format!("{locale}: catalogs cannot be read"))?;
        let errors = locale_root.join("errors");
        if errors.is_dir() {
            files.extend(
                fs::read_dir(&errors)
                    .map_err(|_| format!("{locale}: error catalog directory is missing"))?
                    .map(|entry| entry.map(|entry| entry.path()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| format!("{locale}: error catalogs cannot be read"))?,
            );
        }
        files.sort();
        let sources = files
            .iter()
            .filter(|file| file.extension().is_some_and(|extension| extension == "ftl"))
            .map(|file| {
                fs::read_to_string(file).map_err(|_| format!("{locale}: catalog is not UTF-8"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_sources(locale, &sources, &inventory)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ops::RangeInclusive;

    use super::*;
    #[test]
    fn both_real_locales_cover_public_errors_and_required_parameters_without_fallback() {
        validate_error_catalogs(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/i18n"))
            .unwrap();
    }
    #[test]
    fn public_inventory_covers_typed_errors_without_conflicts() {
        use identity_application::error::codes::{
            authorization::AuthorizationErrorCode, group::GroupErrorCode, rbac::RbacErrorCode,
            user_management::UserManagementErrorCode,
        };
        use std::collections::BTreeSet;
        use strum::IntoEnumIterator;

        fn covered<E: AppErrorCode + IntoEnumIterator>(
            inventory: &[PublicErrorDefinition],
            range: RangeInclusive<u32>,
        ) {
            for code in E::iter() {
                assert!(range.contains(&code.code()));
                let entry = inventory
                    .iter()
                    .find(|entry| entry.code == code.code())
                    .expect("every typed public error must be cataloged");
                assert_eq!(entry.kind, code.kind());
                assert_eq!(entry.fluent_key, format!("E{}", code.code()));
            }
        }

        let inventory = public_error_inventory();
        let codes: BTreeSet<_> = inventory.iter().map(|entry| entry.code).collect();
        let keys: BTreeSet<_> = inventory.iter().map(|entry| &entry.fluent_key).collect();
        assert_eq!(codes.len(), inventory.len());
        assert_eq!(keys.len(), inventory.len());
        for entry in &inventory {
            assert!(!entry.usage_module.is_empty());
            let required: BTreeSet<_> = entry.required.iter().collect();
            let optional: BTreeSet<_> = entry.optional.iter().collect();
            assert_eq!(required.len(), entry.required.len());
            assert_eq!(optional.len(), entry.optional.len());
            assert!(required.is_disjoint(&optional));
            assert!(
                required
                    .iter()
                    .chain(&optional)
                    .all(|name| !name.is_empty())
            );
        }
        covered::<UserManagementErrorCode>(&inventory, 16000..=16099);
        covered::<RbacErrorCode>(&inventory, 17000..=17099);
        covered::<GroupErrorCode>(&inventory, 19000..=19099);
        covered::<AuthorizationErrorCode>(&inventory, 27000..=27099);
    }
    #[test]
    fn missing_keys_and_parameters_and_malformed_fluent_are_rejected() {
        let inventory = [PublicErrorDefinition {
            code: 1,
            kind: ErrorKind::Validation,
            fluent_key: "E1".to_owned(),
            usage_module: "negative",
            required: &["name"],
            optional: &[],
        }];
        for source in [
            "E2 = Other",
            "E1 = Hello",
            "E1 = Hello { $other }",
            "E1 = { invalid syntax",
        ] {
            assert!(
                validate_sources("zh-CN", &[source.to_owned()], &inventory).is_err(),
                "{source}"
            );
        }
        validate_sources("zh-CN", &["E1 = 你好，{ $name }".to_owned()], &inventory).unwrap();
    }
}
