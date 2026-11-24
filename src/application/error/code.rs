use super::kind::ErrorKind;

pub trait AppErrorCode: Copy {
    fn kind(self) -> ErrorKind;
    fn code(self) -> u32;

    /// Parameters the localized message of this code always receives.
    fn required_params(self) -> &'static [&'static str] {
        &[]
    }
}
