define_error_codes! {
    /// Error codes for data protection (encryption/decryption) operations.
    /// Range: 14000-14099
    pub enum DataProtectionErrorCode {
        InvalidProtectedPayload = 14000 { kind: Validation },
        KeyRingEmpty = 14001 { kind: Internal },
        EncryptionFailed = 14002 { kind: Internal },
    }
}
