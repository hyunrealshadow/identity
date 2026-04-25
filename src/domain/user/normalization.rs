#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmailNormalizationError {
    Empty,
    InvalidFormat,
    InvalidDomain,
}

pub fn normalize_username(username: &str) -> Option<String> {
    let username = username.trim();
    (!username.is_empty()).then(|| username.to_lowercase())
}

pub fn normalize_email(email: &str) -> Result<String, EmailNormalizationError> {
    let email = email.trim();
    if email.is_empty() {
        return Err(EmailNormalizationError::Empty);
    }

    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default().trim();
    let domain = parts.next().unwrap_or_default().trim();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() || !domain.contains('.') {
        return Err(EmailNormalizationError::InvalidFormat);
    }

    let ascii_domain = idna::domain_to_ascii(domain)
        .map_err(|_| EmailNormalizationError::InvalidDomain)?
        .to_lowercase();
    if ascii_domain.is_empty() || !ascii_domain.contains('.') {
        return Err(EmailNormalizationError::InvalidDomain);
    }

    Ok(format!("{}@{}", local.to_lowercase(), ascii_domain))
}

pub fn normalize_identifier(identifier: &str) -> Option<String> {
    normalize_email(identifier).ok().or_else(|| normalize_username(identifier))
}

#[cfg(test)]
mod tests {
    use super::{normalize_email, normalize_identifier, normalize_username};

    #[test]
    fn normalize_username_trims_and_lowercases() {
        assert_eq!(normalize_username(" Alice "), Some("alice".to_owned()));
    }

    #[test]
    fn normalize_email_lowercases_local_and_punycodes_domain() {
        assert_eq!(
            normalize_email("USER@例子.测试").unwrap(),
            "user@xn--fsqu00a.xn--0zwm56d"
        );
    }

    #[test]
    fn normalize_identifier_accepts_username_or_email() {
        assert_eq!(
            normalize_identifier("USER@EXAMPLE.COM"),
            Some("user@example.com".to_owned())
        );
        assert_eq!(normalize_identifier("Alice"), Some("alice".to_owned()));
    }
}
