use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Argon2Variant {
    #[serde(rename = "id")]
    Argon2id,
    #[serde(rename = "i")]
    Argon2i,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Argon2Version {
    #[serde(rename = "1.3")]
    Argon2013,
    #[serde(rename = "1.0")]
    Argon2010,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Options {
    pub variant: Argon2Variant,
    pub version: Argon2Version,
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Password {
    pub hash: String,
    pub salt: String,
    pub options: Argon2Options,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "algorithm")]
pub enum Password {
    #[serde(rename = "argon2")]
    Argon2(Argon2Password),
}

#[cfg(test)]
mod tests {
    use super::{Argon2Options, Argon2Password, Argon2Variant, Argon2Version, Password};

    #[test]
    fn password_round_trips_through_json() {
        let password = Password::Argon2(Argon2Password {
            hash: "hash".to_owned(),
            salt: "salt".to_owned(),
            options: Argon2Options {
                variant: Argon2Variant::Argon2id,
                version: Argon2Version::Argon2013,
                time_cost: 3,
                memory_cost: 65_536,
                parallelism: 1,
            },
        });

        let json = serde_json::to_string(&password).unwrap();
        let decoded: Password = serde_json::from_str(&json).unwrap();

        assert!(matches!(decoded, Password::Argon2(_)));
    }
}
