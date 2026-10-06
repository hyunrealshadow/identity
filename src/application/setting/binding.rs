use std::{collections::HashMap, sync::Arc, vec::IntoIter};

use serde::Deserialize;
use serde_json::{Map, Value, to_value};
use tracing::{error, warn};

use super::{SettingDefinition, SettingError, SettingSection};

/// A consistent view of every registered setting, refreshed as one unit.
///
/// Each value is the validated JSON of its key.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SettingsSnapshot {
    values: HashMap<String, Value>,
}

impl SettingsSnapshot {
    /// The value of `S`, or its declared default when `S` is absent.
    #[must_use]
    pub fn get<S: SettingDefinition>(&self) -> S::Value {
        self.values
            .get(S::KEY)
            .and_then(|value| S::Value::deserialize(value).ok())
            .unwrap_or_else(S::default_value)
    }

    /// The section `T`, bound from every setting under `T::PREFIX`.
    #[must_use]
    pub fn section<T: SettingSection>(&self) -> T {
        let mut entries = self
            .values
            .iter()
            .filter_map(|(key, value)| Some((key, section_path(key, T::PREFIX)?, value)))
            .collect::<Vec<_>>();
        // Parents first, so a child key refines the object stored above it.
        entries.sort_unstable_by_key(|(key, ..)| *key);
        let mut tree = Value::Object(Map::new());
        for (_, path, value) in entries {
            merge_at(&mut tree, &path, value.clone());
        }
        match T::deserialize(tree) {
            Ok(section) => match section.validate() {
                Ok(()) => section,
                Err(error) => {
                    error!(section = T::PREFIX, error = %error, "failed to validate setting section");
                    T::default()
                }
            },
            Err(error) => {
                error!(section = T::PREFIX, error = %error, "failed to bind setting section");
                T::default()
            }
        }
    }

    #[must_use]
    pub fn with<S: SettingDefinition>(mut self, value: S::Value) -> Self {
        if let Ok(value) = to_value(value) {
            self.values.insert(S::KEY.to_owned(), value);
        }
        self
    }

    /// Binds a section into separate dotted keys, updating any keys already
    /// present and inserting its declared fields when absent.
    #[must_use]
    pub fn with_section<T: SettingSection>(mut self, section: &T) -> Self {
        let Ok(tree) = to_value(section) else {
            return self;
        };
        for (key, value) in &mut self.values {
            let found = section_path(key, T::PREFIX)
                .and_then(|path| path.iter().try_fold(&tree, |node, part| node.get(part)));
            if let Some(found) = found {
                value.clone_from(found);
            }
        }
        for (key, _, value) in section_leaves::<T>(&tree) {
            self.values.entry(key).or_insert(value);
        }
        self
    }

    /// Keys whose value in `next` differs from the value in `self`.
    pub fn changed_keys<'a>(&'a self, next: &'a Self) -> impl Iterator<Item = &'a str> + 'a {
        next.values
            .iter()
            .filter(|(key, value)| self.values.get(*key) != Some(*value))
            .map(|(key, _)| key.as_str())
    }
}

fn section_path<'a>(key: &'a str, prefix: &str) -> Option<Vec<&'a str>> {
    let rest = key.strip_prefix(prefix)?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    Some(rest.strip_prefix('.')?.split('.').collect())
}

fn merge_at(node: &mut Value, path: &[&str], value: Value) {
    let Some((head, rest)) = path.split_first() else {
        merge(node, value);
        return;
    };
    if !node.is_object() {
        *node = Value::Object(Map::new());
    }
    if let Value::Object(children) = node {
        merge_at(children.entry(*head).or_insert(Value::Null), rest, value);
    }
}

fn merge(node: &mut Value, value: Value) {
    match (node, value) {
        (Value::Object(node), Value::Object(value)) => {
            for (key, child) in value {
                merge(node.entry(key).or_insert(Value::Null), child);
            }
        }
        (node, value) => *node = value,
    }
}

fn section_leaves<T: SettingSection>(value: &Value) -> Vec<(String, Vec<String>, Value)> {
    fn visit(
        prefix: &str,
        object_fields: &[&str],
        path: &mut Vec<String>,
        value: &Value,
        leaves: &mut Vec<(String, Vec<String>, Value)>,
    ) {
        if let Value::Object(fields) = value
            && !fields.is_empty()
            && !object_fields.contains(&path.join(".").as_str())
        {
            for (name, child) in fields {
                path.push(name.clone());
                visit(prefix, object_fields, path, child, leaves);
                path.pop();
            }
        } else if !path.is_empty() {
            leaves.push((
                format!("{prefix}.{}", path.join(".")),
                path.clone(),
                value.clone(),
            ));
        }
    }

    let mut leaves = Vec::new();
    visit(
        T::PREFIX,
        T::OBJECT_FIELDS,
        &mut Vec::new(),
        value,
        &mut leaves,
    );
    leaves
}

/// Where consumers read the current settings snapshot from.
pub trait SettingsSource: Send + Sync {
    fn snapshot(&self) -> Arc<SettingsSnapshot>;
}

impl SettingsSource for SettingsSnapshot {
    fn snapshot(&self) -> Arc<SettingsSnapshot> {
        Arc::new(self.clone())
    }
}

/// A typed batch of setting writes, validated before it reaches storage.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SettingChanges {
    values: Vec<(String, Value)>,
}

impl SettingChanges {
    /// Adds `value` for `S`, replacing an earlier value for the same key.
    pub fn set<S: SettingDefinition>(mut self, value: &S::Value) -> Result<Self, SettingError> {
        S::validate(value).map_err(|error| SettingError::Validation(error.message().to_owned()))?;
        let value = to_value(value).map_err(SettingError::Serialize)?;
        self.values.retain(|(key, _)| *key != S::KEY);
        self.values.push((S::KEY.to_owned(), value));
        Ok(self)
    }

    /// Writes the fields of a section as separate dotted keys.
    pub fn set_section<T: SettingSection>(mut self, section: &T) -> Result<Self, SettingError> {
        section
            .validate()
            .map_err(|error| SettingError::Validation(error.message().to_owned()))?;
        let value = to_value(section).map_err(SettingError::Serialize)?;
        for (key, _, value) in section_leaves::<T>(&value) {
            self.values.retain(|(existing, _)| existing != &key);
            self.values.push((key, value));
        }
        Ok(self)
    }

    /// Writes one storage field of a section, leaving its other keys alone.
    pub fn set_section_field<T: SettingSection>(
        mut self,
        section: &T,
        path: &str,
    ) -> Result<Self, SettingError> {
        section
            .validate()
            .map_err(|error| SettingError::Validation(error.message().to_owned()))?;
        let value = to_value(section).map_err(SettingError::Serialize)?;
        let key = format!("{}.{}", T::PREFIX, path);
        let (_, _, value) = section_leaves::<T>(&value)
            .into_iter()
            .find(|(candidate, _, _)| candidate == &key)
            .ok_or_else(|| SettingError::Validation(format!("unknown setting field `{key}`")))?;
        self.values.retain(|(existing, _)| existing != &key);
        self.values.push((key, value));
        Ok(self)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl IntoIterator for SettingChanges {
    type Item = (String, Value);
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

type SettingValidator = dyn Fn(&Value) -> Result<(), SettingError> + Send + Sync;

/// The type-erased decoding rules of one [`SettingDefinition`].
#[derive(Clone)]
struct SettingDescriptor {
    key: String,
    check: Arc<SettingValidator>,
    default_json: Value,
}

impl SettingDescriptor {
    fn of<S: SettingDefinition>() -> Self {
        Self {
            key: S::KEY.to_owned(),
            check: Arc::new(check::<S>),
            default_json: to_value(S::default_value()).expect("setting default must serialize"),
        }
    }
}

fn check<S: SettingDefinition>(raw: &Value) -> Result<(), SettingError> {
    S::decode(raw).map(drop)
}

/// The settings kept in the key-value setting store, and how to decode them.
#[derive(Clone, Default)]
pub struct SettingRegistry {
    descriptors: Vec<SettingDescriptor>,
}

impl SettingRegistry {
    /// # Panics
    ///
    /// Panics when another setting with the same key is already registered.
    #[must_use]
    pub fn register<S: SettingDefinition>(mut self) -> Self {
        assert!(
            self.descriptors.iter().all(|entry| entry.key != S::KEY),
            "setting `{}` is registered twice",
            S::KEY
        );
        self.descriptors.push(SettingDescriptor::of::<S>());
        self
    }

    /// Registers every field of a section as its own dotted storage key.
    #[must_use]
    pub fn register_section<T: SettingSection>(mut self) -> Self {
        let defaults = to_value(T::default()).expect("setting section default must serialize");
        for (key, path, default_json) in section_leaves::<T>(&defaults) {
            assert!(
                self.descriptors.iter().all(|entry| entry.key != key),
                "setting `{key}` is registered twice"
            );
            let template = defaults.clone();
            let check = move |raw: &Value| {
                let mut tree = template.clone();
                let path = path.iter().map(String::as_str).collect::<Vec<_>>();
                merge_at(&mut tree, &path, raw.clone());
                let section = T::deserialize(tree).map_err(SettingError::Deserialize)?;
                section
                    .validate()
                    .map_err(|error| SettingError::Validation(error.message().to_owned()))
            };
            self.descriptors.push(SettingDescriptor {
                key,
                check: Arc::new(check),
                default_json,
            });
        }
        self
    }

    /// Serialized default of every registered setting, for seeding the store.
    pub fn defaults(&self) -> Result<Vec<(String, Value)>, SettingError> {
        Ok(self
            .descriptors
            .iter()
            .map(|entry| (entry.key.clone(), entry.default_json.clone()))
            .collect())
    }

    /// Validates the stored values into one snapshot.
    ///
    /// A missing value takes its declared default. A value that fails to
    /// decode keeps its `previous` value, and fails the load only when there
    /// is none.
    pub fn resolve(
        &self,
        raw: &HashMap<String, Value>,
        previous: Option<&SettingsSnapshot>,
    ) -> Result<SettingsSnapshot, SettingError> {
        let mut values = HashMap::with_capacity(self.descriptors.len());
        for entry in &self.descriptors {
            let value = match raw.get(&entry.key) {
                None => entry.default_json.clone(),
                Some(stored) => match (
                    (entry.check)(stored),
                    previous.and_then(|snapshot| snapshot.values.get(&entry.key)),
                ) {
                    (Ok(()), _) => stored.clone(),
                    (Err(error), Some(previous)) => {
                        warn!(key = %entry.key, error = %error, "failed to refresh setting");
                        previous.clone()
                    }
                    (Err(error), None) => return Err(error),
                },
            };
            values.insert(entry.key.clone(), value);
        }
        Ok(SettingsSnapshot { values })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::{Deserialize, Serialize};
    use serde_json::{Value, json, to_value};

    use super::{SettingChanges, SettingRegistry, SettingsSnapshot};
    use crate::setting::{
        DeviceAuthorizationSettings, SettingDefinition, SettingSection, SettingValidationError,
    };

    struct TestDynamicSetting;

    impl SettingDefinition for TestDynamicSetting {
        type Value = bool;
        const KEY: &'static str = "test.dynamic_registration.enabled";

        fn default_value() -> bool {
            false
        }
    }

    struct TestDeviceSetting;

    impl SettingDefinition for TestDeviceSetting {
        type Value = DeviceAuthorizationSettings;
        const KEY: &'static str = "test.device_authorization";

        fn default_value() -> Self::Value {
            DeviceAuthorizationSettings::default()
        }

        fn validate(value: &Self::Value) -> Result<(), SettingValidationError> {
            if value.request_ttl_seconds < 1 || value.polling_interval_seconds < 1 {
                return Err(SettingValidationError::new("invalid device interval"));
            }
            Ok(())
        }
    }

    struct Greeting;

    impl SettingDefinition for Greeting {
        type Value = Option<String>;
        const KEY: &'static str = "greeting";

        fn default_value() -> Self::Value {
            None
        }
    }

    fn registry() -> SettingRegistry {
        SettingRegistry::default()
            .register::<Greeting>()
            .register::<TestDynamicSetting>()
            .register::<TestDeviceSetting>()
    }

    fn raw(entries: &[(&str, Value)]) -> HashMap<String, Value> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect()
    }

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    #[serde(default)]
    struct DynamicRegistration {
        enabled: bool,
    }

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    #[serde(default)]
    struct OpenIdConnect {
        dynamic_registration: DynamicRegistration,
        device_authorization: DeviceAuthorizationSettings,
    }

    impl SettingSection for OpenIdConnect {
        const PREFIX: &'static str = "test";
    }

    #[test]
    fn resolves_stored_values_and_defaults_missing_ones() {
        let snapshot = registry()
            .resolve(&raw(&[(Greeting::KEY, json!("hello"))]), None)
            .unwrap();

        assert_eq!(snapshot.get::<Greeting>().as_deref(), Some("hello"));
        assert!(!snapshot.get::<TestDynamicSetting>());
        assert_eq!(
            snapshot.get::<TestDeviceSetting>(),
            TestDeviceSetting::default_value()
        );
    }

    #[test]
    fn invalid_value_keeps_previous_value_or_fails_the_first_load() {
        let invalid = raw(&[(
            TestDeviceSetting::KEY,
            json!({ "request_ttl_seconds": 0, "polling_interval_seconds": 5 }),
        )]);
        assert!(registry().resolve(&invalid, None).is_err());

        let previous =
            SettingsSnapshot::default().with::<TestDeviceSetting>(DeviceAuthorizationSettings {
                request_ttl_seconds: 30,
                polling_interval_seconds: 2,
            });
        let next = registry().resolve(&invalid, Some(&previous)).unwrap();

        assert_eq!(next.get::<TestDeviceSetting>().request_ttl_seconds, 30);
    }

    #[test]
    fn section_merges_every_key_under_its_prefix() {
        let snapshot = registry()
            .resolve(
                &raw(&[
                    (TestDynamicSetting::KEY, json!(true)),
                    (
                        TestDeviceSetting::KEY,
                        json!({ "request_ttl_seconds": 30, "polling_interval_seconds": 2 }),
                    ),
                ]),
                None,
            )
            .unwrap();

        assert_eq!(
            snapshot.section::<OpenIdConnect>(),
            OpenIdConnect {
                dynamic_registration: DynamicRegistration { enabled: true },
                device_authorization: DeviceAuthorizationSettings {
                    request_ttl_seconds: 30,
                    polling_interval_seconds: 2,
                },
            }
        );
    }

    #[test]
    fn child_keys_refine_an_object_stored_at_their_parent() {
        let snapshot = SettingsSnapshot::default()
            .with::<TestDeviceSetting>(DeviceAuthorizationSettings {
                request_ttl_seconds: 30,
                polling_interval_seconds: 2,
            })
            .with::<PollingInterval>(9);

        let section = snapshot.section::<OpenIdConnect>();

        assert_eq!(section.device_authorization.request_ttl_seconds, 30);
        assert_eq!(section.device_authorization.polling_interval_seconds, 9);
    }

    struct PollingInterval;

    impl SettingDefinition for PollingInterval {
        type Value = i64;
        const KEY: &'static str = "test.device_authorization.polling_interval_seconds";

        fn default_value() -> Self::Value {
            5
        }
    }

    #[test]
    fn with_section_writes_back_into_each_present_key() {
        let section = OpenIdConnect {
            dynamic_registration: DynamicRegistration { enabled: true },
            device_authorization: DeviceAuthorizationSettings {
                request_ttl_seconds: 30,
                polling_interval_seconds: 2,
            },
        };

        let snapshot = registry()
            .resolve(&raw(&[]), None)
            .unwrap()
            .with_section(&section);

        assert!(snapshot.get::<TestDynamicSetting>());
        assert_eq!(
            snapshot.get::<TestDeviceSetting>(),
            section.device_authorization
        );
        assert_eq!(snapshot.get::<Greeting>(), None);
    }

    #[test]
    fn reports_the_keys_that_changed() {
        let registry = registry();
        let previous = registry.resolve(&raw(&[]), None).unwrap();
        let next = registry
            .resolve(&raw(&[(TestDynamicSetting::KEY, json!(true))]), None)
            .unwrap();

        assert_eq!(
            previous.changed_keys(&next).collect::<Vec<_>>(),
            vec![TestDynamicSetting::KEY]
        );
    }

    #[test]
    fn changes_are_validated_and_keep_the_last_value_per_key() {
        let changes = SettingChanges::default()
            .set::<TestDynamicSetting>(&false)
            .unwrap()
            .set::<TestDynamicSetting>(&true)
            .unwrap();
        assert_eq!(
            changes.into_iter().collect::<Vec<_>>(),
            vec![(TestDynamicSetting::KEY.to_owned(), json!(true))]
        );

        let invalid =
            SettingChanges::default().set::<TestDeviceSetting>(&DeviceAuthorizationSettings {
                request_ttl_seconds: 0,
                polling_interval_seconds: 5,
            });
        assert!(invalid.is_err());
    }

    #[test]
    fn defaults_serialize_every_registered_setting() {
        assert_eq!(
            registry().defaults().unwrap(),
            vec![
                (Greeting::KEY.to_owned(), json!(null)),
                (TestDynamicSetting::KEY.to_owned(), json!(false)),
                (
                    TestDeviceSetting::KEY.to_owned(),
                    to_value(TestDeviceSetting::default_value()).unwrap()
                ),
            ]
        );
    }

    #[test]
    #[should_panic(expected = "registered twice")]
    fn rejects_duplicate_registration() {
        let _ = registry().register::<Greeting>();
    }
}
