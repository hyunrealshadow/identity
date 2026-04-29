use std::{env, sync::Once};

use tracing_subscriber::{EnvFilter, fmt};

use crate::config::LoggerConfig;

static TRACING_INIT: Once = Once::new();

pub fn init_tracing(config: &LoggerConfig) {
    if !config.enable {
        return;
    }

    TRACING_INIT.call_once(|| {
        if config.pretty_backtrace {
            unsafe {
                env::set_var("RUST_BACKTRACE", "1");
            }
        }

        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(config.level.clone()));

        let subscriber = fmt().with_env_filter(filter);

        match config.format.as_str() {
            "json" => subscriber.json().init(),
            "pretty" => subscriber.pretty().init(),
            _ => subscriber.compact().init(),
        }
    });
}
