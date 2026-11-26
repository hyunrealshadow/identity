use super::login_challenge_uri;

#[test]
fn challenge_destinations_use_method_paths_and_preserve_context() {
    let locales = vec!["zh-CN".to_owned(), "en-US".to_owned()];
    for (credential, method) in [
        ("password", "password"),
        ("passkey", "passkey"),
        ("otp", "otp"),
        ("recovery_code", "recovery-code"),
    ] {
        assert_eq!(
            login_challenge_uri("rp+login/id", credential, Some(&locales)),
            format!("/login/{method}?login_id=rp%2Blogin%2Fid&ui_locales=zh-CN+en-US"),
        );
    }
}
