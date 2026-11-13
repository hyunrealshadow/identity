use identity_web::graphql;

use identity_infrastructure::i18n::catalog;

use std::env;

fn main() {
    if env::args().nth(1).as_deref() == Some("--management-catalog") {
        use identity_domain::authorization::ManagementScope;
        let catalog = ManagementScope::ALL.into_iter().map(|scope| {
            let definition = scope.definition();
            serde_json::json!({"scope":definition.name,"action":definition.action,
                "authentication":definition.human_authentication.as_str(),"machineAllowed":definition.m2m_allowed(),"reserved":definition.reserved})
        }).collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&catalog).expect("scope catalog is serializable")
        );
        return;
    }
    if env::args().nth(1).as_deref() == Some("--error-catalog") {
        let inventory = catalog::public_error_inventory()
            .into_iter()
            .map(|definition| {
                serde_json::json!({
                    "code": definition.code, "kind": definition.kind.as_str(),
                    "fluentKey": definition.fluent_key, "requiredParams": definition.required,
                    "optionalParams": definition.optional, "module": definition.usage_module,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&inventory).expect("public catalog is serializable")
        );
        return;
    }
    print!("{}", graphql::schema_sdl());
}
