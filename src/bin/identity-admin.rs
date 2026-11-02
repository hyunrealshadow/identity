use identity_domain::{
    authorization::{GrantReason, RequestId},
    user::UserOid,
};
use identity_infrastructure::{config::AppConfig, database, web::tera::build_i18n};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5
        || args[0] != "bootstrap-owner"
        || args[1] != "--user"
        || args[3] != "--reason"
    {
        return Err("Usage: identity-admin bootstrap-owner --user <UUID> --reason <reason>".into());
    }
    let request_id = RequestId::new(uuid::Uuid::new_v4().to_string())?;
    let (config, _) = AppConfig::load()?;
    let db = database::connect(&config.database).await?;
    let i18n = build_i18n()?;
    let locale = std::env::var("LANG")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(i18n.fallback_locale().clone());
    let user = UserOid(args[2].parse()?);
    let reason = GrantReason::new(args[4].clone())?;
    match database::owner_bootstrap::bootstrap_owner(&db, user, reason, request_id.clone()).await {
        Ok(membership) => {
            println!("membership={membership} requestId={request_id}");
            Ok(())
        }
        Err(error) => {
            eprintln!(
                "{} code={} requestId={request_id}",
                i18n.t_code_with_params(&locale, error.code(), error.params()),
                error.code()
            );
            Err("owner bootstrap rejected".into())
        }
    }
}
