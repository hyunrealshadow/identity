use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsymmetricKeyAlgorithm {
    Rsa { bits: usize },
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    EcdsaSecp256k1,
    Ed25519,
    Ed448,
}

impl AsymmetricKeyAlgorithm {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Rsa { bits } if *bits < 2048 => Err("rsa bits must be at least 2048".to_owned()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AsymmetricKeyAlgorithm;

    #[test]
    fn rejects_rsa_below_2048_bits() {
        let result = AsymmetricKeyAlgorithm::Rsa { bits: 1024 }.validate();

        assert_eq!(result, Err("rsa bits must be at least 2048".to_owned()));
    }
}
