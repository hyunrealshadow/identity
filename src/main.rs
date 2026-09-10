use identity::{
    application::observability::{BusinessEvent, EventValue, event_sink},
    boot::{AppBuilder, AppResult, server},
    infrastructure::observability,
    web,
};

#[tokio::main]
async fn main() -> AppResult<()> {
    let builder = AppBuilder::from_config()?
        .init_tracing()?
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
    let internal = web::router::internal_router(
        state.clone(),
        &config,
        state.services().workload_authenticator().clone(),
    );

    event_sink().emit(
        BusinessEvent::business("service.started")
            .outcome("success")
            .attribute(
                "environment",
                EventValue::Text(state.context().environment().as_str().to_owned()),
            ),
    );

    let result = server::start_servers(&state, &config, app, internal).await;

    event_sink().emit(BusinessEvent::business("service.stopped").outcome("success"));
    observability::shutdown(std::time::Duration::from_secs(5));
    result
}
