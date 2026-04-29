pub mod error;
pub mod protector;

pub use protector::{
    DATA_PROTECTION_KEY_SIZE, DataProtectionCipher, DataProtector, DataProtectorImpl,
};
