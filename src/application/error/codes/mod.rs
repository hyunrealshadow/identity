pub mod auth;
pub mod authorize;
pub mod authorize_http;
pub mod common;
pub mod data_protection;
pub mod install;
pub mod key;
pub mod openid_connect;
pub mod provider;
pub mod registration;
pub mod token;

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, ops::RangeInclusive};

    use regex::Regex;

    const CODE_MODULES: &[(&str, &str, RangeInclusive<u32>)] = &[
        ("common", include_str!("common.rs"), 10000..=10099),
        ("auth", include_str!("auth.rs"), 11000..=11099),
        ("key", include_str!("key.rs"), 12000..=12099),
        ("install", include_str!("install.rs"), 13000..=13099),
        (
            "data_protection",
            include_str!("data_protection.rs"),
            14000..=14099,
        ),
        ("provider", include_str!("provider.rs"), 20000..=20099),
        (
            "openid_connect",
            include_str!("openid_connect.rs"),
            21000..=21099,
        ),
        (
            "authorize_http",
            include_str!("authorize_http.rs"),
            22000..=22099,
        ),
        ("authorize", include_str!("authorize.rs"), 23000..=23099),
        ("token", include_str!("token.rs"), 24000..=24099),
        (
            "registration",
            include_str!("registration.rs"),
            25000..=25099,
        ),
    ];

    #[test]
    fn error_codes_are_five_digit_unique_and_module_scoped() {
        let code_pattern = Regex::new(r"=>\s*(\d+)").expect("regex should compile");
        let mut seen = HashSet::new();

        for (module, source, range) in CODE_MODULES {
            let mut module_code_count = 0;

            for captures in code_pattern.captures_iter(source) {
                let code = captures[1].parse::<u32>().expect("code should be numeric");
                module_code_count += 1;

                assert!(
                    (10000..=99999).contains(&code),
                    "{module} code {code} is not five digits"
                );
                assert!(
                    range.contains(&code),
                    "{module} code {code} is outside module range {range:?}"
                );
                assert!(seen.insert(code), "duplicate application error code {code}");
            }

            assert!(module_code_count > 0, "{module} has no error codes");
        }
    }
}
