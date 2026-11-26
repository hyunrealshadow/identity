define_error_codes! {
    /// Range: 12000-12099
    pub enum KeyErrorCode(module = "key") {
        NotFound = 12000 { kind: NotFound },
        Revoked = 12001 { kind: Unauthorized },
        UnsupportedAlgorithm = 12002 { kind: Validation, required: [algorithm] },
        InvalidCertificatePem = 12003 { kind: Validation },
        InvalidKeyType = 12004 { kind: Validation },
        CertificateRequiresAsymmetricKey = 12005 { kind: Validation },
        JwkGenerationFailed = 12006 { kind: Internal },
        JwkSerializationFailed = 12007 { kind: Internal },
    }
}
