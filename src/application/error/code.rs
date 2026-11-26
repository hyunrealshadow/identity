use super::kind::ErrorKind;

pub trait AppErrorCode: Copy {
    fn kind(self) -> ErrorKind;
    fn code(self) -> u32;

    /// Parameters the localized message of this code always receives.
    fn required_params(self) -> &'static [&'static str] {
        &[]
    }

    /// Parameters the localized message of this code may optionally receive.
    fn optional_params(self) -> &'static [&'static str] {
        &[]
    }

    /// Optional per-variant module path shown in the exported error catalog.
    /// When `None`, the catalog falls back to the enum's module name.
    fn usage_module(self) -> Option<&'static str> {
        None
    }
}
