//! Rendering a server-side view in the request's language.

use http::HeaderMap;
use serde::Serialize;
use serde_json::{Value as SerdeJsonValue, to_value};
use tera::Context;
use tracing::error;

use crate::{
    application::error::{AppError, codes::common},
    infrastructure::{AppState, i18n::resolve_locale_from_headers, templates::with_locale},
};

pub fn render_view<T: Serialize>(
    state: &AppState,
    headers: &HeaderMap,
    template: &str,
    data: T,
) -> Result<String, AppError> {
    match to_value(data) {
        Err(e) => {
            error!(error = %e, "render_view: serialise failed");
            Err(common::error::InternalError.into())
        }
        Ok(mut data) => {
            let locale = resolve_locale_from_headers(headers).to_string();
            if let Some(object) = data.as_object_mut() {
                object
                    .entry("lang")
                    .or_insert_with(|| SerdeJsonValue::String(locale));
            }

            match Context::from_serialize(&data) {
                Err(e) => {
                    error!(error = %e, "render_view: context build failed");
                    Err(common::error::InternalError.into())
                }
                Ok(context) => match with_locale(
                    state.resources().tera(),
                    state.resources().i18n().loader(),
                    resolve_locale_from_headers(headers),
                )
                .render(template, &context)
                {
                    Ok(body) => Ok(body),
                    Err(e) => {
                        error!(error = %e, template, "render_view: template render failed");
                        Err(common::error::InternalError.into())
                    }
                },
            }
        }
    }
}
