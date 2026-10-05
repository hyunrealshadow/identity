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
