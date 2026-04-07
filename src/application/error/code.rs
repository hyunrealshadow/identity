use super::kind::ErrorKind;

pub trait AppErrorCode: Copy {
    fn kind(self) -> ErrorKind;
    fn code(self) -> u32;
}
