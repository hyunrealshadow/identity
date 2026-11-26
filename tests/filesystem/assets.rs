use identity_application::error::params::ErrorParams;
use identity_infrastructure::{i18n::build_i18n, templates::build_tera};
use unic_langid::langid;

#[test]
fn build_i18n_loads_split_error_files_with_args() {
    let i18n = build_i18n().expect("i18n should load from assets/i18n");
    let params = ErrorParams::new()
        .insert("identifier", "alice@example.com")
        .insert("identifier_kind", "email");

    let translated = i18n.t_code_with_params(&langid!("en-US"), 11000, &params);

    assert_eq!(
        translated,
        "The account does not exist. Enter a different email or username."
    );
}

#[test]
fn build_tera_loads_runtime_templates_from_assets_views() {
    let tera = build_tera(None).expect("tera should load templates from assets/views");
    let template_names = tera.get_template_names().collect::<Vec<_>>();

    for expected in [
        "error.html",
        "oauth2/form_post.html",
        "openid/check_session.html",
        "openid/logout.html",
    ] {
        assert!(template_names.contains(&expected), "missing {expected}");
    }
}
