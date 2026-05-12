use identity_domain::key::{Key, KeyData};

/// Detect which JWE encryption algorithms a key supports.
pub fn detect_encryption_algorithms(key: &Key) -> Vec<String> {
    let KeyData::Asymmetric(data) = &key.data else {
        return vec![];
    };

    let pem = &data.private_key;
    if pem.contains("BEGIN RSA") || (pem.contains("BEGIN PUBLIC KEY") && !pem.contains("BEGIN EC")) {
        vec![
            "RSA-OAEP".to_owned(),
            "RSA-OAEP-256".to_owned(),
        ]
    } else if pem.contains("BEGIN EC") {
        vec![
            "ECDH-ES".to_owned(),
            "ECDH-ES+A128KW".to_owned(),
            "ECDH-ES+A256KW".to_owned(),
        ]
    } else if pem.contains("X25519") || pem.contains("X448") {
        vec![
            "ECDH-ES".to_owned(),
            "ECDH-ES+A128KW".to_owned(),
            "ECDH-ES+A256KW".to_owned(),
        ]
    } else {
        vec![
            "ECDH-ES".to_owned(),
            "ECDH-ES+A128KW".to_owned(),
        ]
    }
}
