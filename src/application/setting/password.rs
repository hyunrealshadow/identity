use crate::{
    auth::password::HashOptions,
    user::model::{Argon2Options, Argon2Variant, Argon2Version},
};

use super::{SettingDefinition, SettingValidationError};

pub struct PasswordHashSetting;

impl SettingDefinition for PasswordHashSetting {
    type Value = HashOptions;

    const KEY: &'static str = "auth.password.hash_options";

    fn default_value() -> Self::Value {
        HashOptions::Argon2(Argon2Options {
            variant: Argon2Variant::Argon2id,
            version: Argon2Version::Argon2013,
            time_cost: 3,
            memory_cost: 65536,
            parallelism: 4,
        })
    }

    fn validate(value: &Self::Value) -> Result<(), SettingValidationError> {
        match value {
            HashOptions::Argon2(options) => {
                if options.time_cost == 0 {
                    return Err(SettingValidationError::new(
                        "argon2 time_cost must be greater than 0",
                    ));
                }

                if options.memory_cost == 0 {
                    return Err(SettingValidationError::new(
                        "argon2 memory_cost must be greater than 0",
                    ));
                }

                if options.parallelism == 0 {
                    return Err(SettingValidationError::new(
                        "argon2 parallelism must be greater than 0",
                    ));
                }

                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HashOptions, PasswordHashSetting};
    use crate::setting::SettingDefinition;
    use crate::user::model::{Argon2Options, Argon2Variant, Argon2Version};

    fn invalid_options(update: impl FnOnce(&mut Argon2Options)) -> HashOptions {
        let mut options = Argon2Options {
            variant: Argon2Variant::Argon2id,
            version: Argon2Version::Argon2013,
            time_cost: 3,
            memory_cost: 65_536,
            parallelism: 4,
        };
        update(&mut options);
        HashOptions::Argon2(options)
    }

    #[test]
    fn default_hash_setting_is_valid() {
        let value = PasswordHashSetting::default_value();
        assert!(PasswordHashSetting::validate(&value).is_ok());
    }

    #[test]
    fn rejects_zero_time_cost() {
        let result =
            PasswordHashSetting::validate(&invalid_options(|options| options.time_cost = 0));

        assert!(matches!(
            result,
            Err(error) if error.message() == "argon2 time_cost must be greater than 0"
        ));
    }

    #[test]
    fn rejects_zero_memory_cost() {
        let result =
            PasswordHashSetting::validate(&invalid_options(|options| options.memory_cost = 0));

        assert!(matches!(
            result,
            Err(error) if error.message() == "argon2 memory_cost must be greater than 0"
        ));
    }

    #[test]
    fn rejects_zero_parallelism() {
        let result =
            PasswordHashSetting::validate(&invalid_options(|options| options.parallelism = 0));

        assert!(matches!(
            result,
            Err(error) if error.message() == "argon2 parallelism must be greater than 0"
        ));
    }
}
