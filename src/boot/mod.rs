mod builder;
mod context;
mod install_guard;
mod lifecycle;
mod resources;
pub mod server;
mod services;
mod settings;
mod state;

use std::error::Error;

pub use self::builder::AppBuilder;
pub use self::context::AppContext;
pub use self::lifecycle::AppLifecycle;
pub use self::resources::AppResources;
pub use self::state::AppState;

pub type AppResult<T> = Result<T, Box<dyn Error + Send + Sync + 'static>>;
