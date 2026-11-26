//! Trusted public-error inventory and direct, fallback-free Fluent validation.
use fluent_templates::{
    FluentBundle,
    fluent_bundle::{FluentArgs, FluentResource},
};
pub use identity_application::error::catalog::{PublicErrorDefinition, public_error_inventory};
use std::{fs, path::Path};
use unic_langid::LanguageIdentifier;

use crate::web::tera as web_tera;

fn validate_sources(
    locale: &str,
    sources: &[String],
    inventory: &[PublicErrorDefinition],
) -> Result<(), String> {
    use std::collections::BTreeSet;
    let language = locale
        .parse::<LanguageIdentifier>()
        .map_err(|_| "invalid catalog locale".to_owned())?;
    let mut bundle = FluentBundle::new_concurrent(vec![language]);
    web_tera::register_list_function(&mut bundle);
    bundle.set_use_isolating(false);
    let mut declared_error_keys = BTreeSet::new();
    for source in sources {
        let resource = FluentResource::try_new(source.clone())
            .map_err(|_| format!("{locale}: invalid Fluent syntax"))?;
        for line in source.lines() {
            if line.starts_with(char::is_whitespace) {
                continue;
            }
            if let Some((raw_key, _)) = line.split_once('=') {
                let key = raw_key.trim_end();
                if let Some(digits) = key.strip_prefix('E')
                    && !digits.is_empty()
                    && digits.bytes().all(|byte| byte.is_ascii_digit())
                {
                    declared_error_keys.insert(key.to_owned());
                }
            }
        }
        bundle
            .add_resource(resource)
            .map_err(|_| format!("{locale}: duplicate Fluent key"))?;
    }
    let registered_keys: BTreeSet<&str> = inventory
        .iter()
        .map(|definition| definition.fluent_key.as_str())
        .collect();
    for key in declared_error_keys {
        if !registered_keys.contains(key.as_str()) {
            return Err(format!("{locale}: orphan error message {key}"));
        }
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

    use identity_application::error::{
        code::AppErrorCode,
        codes::{
            audit::AuditErrorCode, authorization::AuthorizationErrorCode, client::ClientErrorCode,
            group::GroupErrorCode, instance::InstanceErrorCode, rbac::RbacErrorCode,
            user_management::UserManagementErrorCode,
        },
        kind::ErrorKind,
    };

    use super::*;
    #[test]
    fn both_real_locales_cover_public_errors_and_required_parameters_without_fallback() {
        validate_error_catalogs(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/i18n"))
            .unwrap();
    }
    #[test]
    fn public_inventory_covers_typed_errors_without_conflicts() {
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
        covered::<ClientErrorCode>(&inventory, 18000..=18099);
        covered::<GroupErrorCode>(&inventory, 19000..=19099);
        covered::<AuthorizationErrorCode>(&inventory, 27000..=27099);
        covered::<InstanceErrorCode>(&inventory, 29000..=29099);
        covered::<AuditErrorCode>(&inventory, 30000..=30099);
    }
    #[test]
    fn missing_keys_and_parameters_and_malformed_fluent_are_rejected() {
        let inventory = [PublicErrorDefinition {
            code: 1,
            group: "NegativeErrorCode",
            name: "Negative",
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
            "E1 = 你好，{ $name }\nE99999 = Orphan",
        ] {
            assert!(
                validate_sources("zh-CN", &[source.to_owned()], &inventory).is_err(),
                "{source}"
            );
        }
        validate_sources("zh-CN", &["E1 = 你好，{ $name }".to_owned()], &inventory).unwrap();
    }
}
