use identity::{
    boot::{AppBuilder, AppResult, server},
    web,
};

#[tokio::main]
async fn main() -> AppResult<()> {
    let builder = AppBuilder::from_config()?
        .init_tracing()
        .connect_database()
        .await?
        .maybe_auto_install()
        .await?
        .init_i18n_and_templates()?;

    let (state, config) = builder
        .load_runtime_settings()
        .await?
        .build_services()?
        .build();

    let app = web::router::app_router(state.clone(), &config);
    server::start_servers(&state, &config, app).await
}
