//! The Tera template engine with the localization and asset functions the
//! views call. Rendering a view for a request lives in the web layer.

use std::{collections::HashMap, error::Error as StdError, fs, sync::Arc};

use fluent_templates::{ArcLoader, Loader};
use tera::{Error, Function, Kwargs, State, Tera, TeraResult, Value};
use tracing::warn;
use unic_langid::{LanguageIdentifier, langid};

use crate::assets::workspace_path;

struct LocaleAwareFluentLoader {
    loader: Option<Arc<ArcLoader>>,
    default_locale: LanguageIdentifier,
}

impl Function<TeraResult<Value>> for LocaleAwareFluentLoader {
    fn call(&self, args: Kwargs, _: &State) -> TeraResult<Value> {
        let key = args.must_get::<String>("key")?;

        let locale = match args.get::<String>("lang")? {
            Some(lang) => lang
                .parse()
                .map_err(|e| Error::message(format!("t(): invalid `lang` value: {e}")))?,
            None => self.default_locale.clone(),
        };

        let loader = self
            .loader
            .as_ref()
            .ok_or_else(|| Error::message("t(): localization is disabled"))?;
        Ok(Value::from(loader.lookup(&locale, &key).to_string()))
    }
}

/// URL of a built static asset: `asset(path="css/error.css")` answers its
/// content-hashed file from `assets/static/manifest.json`, which
/// `pnpm build:error-css` writes. A path missing from the manifest keeps its
/// plain `/static/` URL.
struct StaticAssetUrls {
    files: HashMap<String, String>,
}

impl StaticAssetUrls {
    fn load() -> Self {
        let path = workspace_path("assets/static/manifest.json");
        let files = match fs::read_to_string(&path) {
            Ok(content) => Self::parse(&content).unwrap_or_else(|e| {
                warn!(error = %e, "static asset manifest is invalid; using unversioned URLs");
                HashMap::new()
            }),
            Err(e) => {
                warn!(error = %e, "static asset manifest is missing; run `pnpm build:error-css`");
                HashMap::new()
            }
        };
        Self { files }
    }

    fn parse(content: &str) -> serde_json::Result<HashMap<String, String>> {
        serde_json::from_str(content)
    }

    fn url(&self, path: &str) -> String {
        let file = self.files.get(path).map_or(path, String::as_str);
        format!("/static/{file}")
    }
}

impl Function<TeraResult<Value>> for StaticAssetUrls {
    fn call(&self, args: Kwargs, _: &State) -> TeraResult<Value> {
        let path = args.must_get::<String>("path")?;
        Ok(Value::from(self.url(&path)))
    }
}

pub fn build_tera(
    loader: Option<Arc<ArcLoader>>,
) -> Result<Arc<Tera>, Box<dyn StdError + Send + Sync + 'static>> {
    let template_glob = workspace_path("assets/views/**/*");
    let mut tera = Tera::new();
    tera.register_function(
        "t",
        LocaleAwareFluentLoader {
            loader,
            default_locale: langid!("en-US"),
        },
    );
    tera.register_function("asset", StaticAssetUrls::load());
    tera.load_from_glob(template_glob.to_string_lossy().as_ref())?;
    Ok(Arc::new(tera))
}

/// A copy of `tera` whose `t()` defaults to `locale`.
pub fn with_locale(
    tera: &Tera,
    loader: Option<Arc<ArcLoader>>,
    locale: LanguageIdentifier,
) -> Tera {
    let mut tera = tera.clone();
    if let Some(loader) = loader {
        tera.register_function(
            "t",
            LocaleAwareFluentLoader {
                loader: Some(loader),
                default_locale: locale,
            },
        );
    }
    tera
}

#[cfg(test)]
mod tests {
    use super::{StaticAssetUrls, build_tera};

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

    #[test]
    fn asset_urls_follow_the_manifest_and_keep_unknown_paths() {
        let urls = StaticAssetUrls {
            files: StaticAssetUrls::parse(r#"{"css/error.css":"css/error.0123456789abcdef.css"}"#)
                .unwrap(),
        };

        assert_eq!(
            urls.url("css/error.css"),
            "/static/css/error.0123456789abcdef.css"
        );
        assert_eq!(urls.url("css/other.css"), "/static/css/other.css");
    }
}
