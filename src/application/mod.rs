extern crate identity_domain as domain;
extern crate self as application;

pub mod auth;
pub mod data_protection;
pub mod error;
pub mod install;
pub mod key;
pub mod openid_connect;
pub mod setting;

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    #[test]
    fn application_layer_does_not_depend_on_infrastructure() {
        let mut violations = Vec::new();
        collect_infrastructure_references(Path::new("src/application"), &mut violations);

        assert!(
            violations.is_empty(),
            "application layer must not depend on infrastructure:\n{}",
            violations.join("\n")
        );
    }

    fn collect_infrastructure_references(path: &Path, violations: &mut Vec<String>) {
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                collect_infrastructure_references(&entry.unwrap().path(), violations);
            }
            return;
        }

        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            return;
        }

        let content = fs::read_to_string(path).unwrap();
        let forbidden = [
            "crate::infra".to_owned() + "structure",
            "infra".to_owned() + "structure::",
        ];
        for (index, line) in content.lines().enumerate() {
            if forbidden.iter().any(|pattern| line.contains(pattern)) {
                violations.push(format!("{}:{}", path.display(), index + 1));
            }
        }
    }
}
