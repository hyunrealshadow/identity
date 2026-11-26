//! Instance settings and key management error catalog. Reserved range:
//! 29000-29099.
//!
//! Management authority, audit and step-up failures keep using the
//! authorization catalog; cursor and page-argument failures keep using the
//! shared business RBAC codes.

define_error_codes! {
    pub enum InstanceErrorCode(module = "instance") {
        VersionConflict = 29000 { kind: Conflict, optional: [current_version] },
        SettingOutOfRange = 29001 { kind: Validation, required: [min, max] },
        InvalidClientMutationId = 29002 { kind: Validation, required: [max] },
        StorageFailed = 29003 { kind: Internal },
        KeyNotFound = 29004 { kind: NotFound },
        KeyNotCurrent = 29005 { kind: Conflict },
        LastActiveKey = 29006 { kind: Conflict },
        KeyAlreadyRevoked = 29007 { kind: Conflict },
        UnsupportedKeyAlgorithm = 29008 { kind: Validation, required: [algorithm] },
        EmailDeliveryNotConfigured = 29009 { kind: Conflict },
        InvalidEmailTemplate = 29010 { kind: Validation, required: [detail] },
        TestEmailFailed = 29011 { kind: Internal, required: [detail] },
        EmailSettingRequired = 29012 { kind: Validation },
        InvalidEmailAddress = 29013 { kind: Validation },
        InvalidEmailTokenEndpoint = 29014 { kind: Validation },
        UnsupportedEmailLocale = 29015 { kind: Validation, required: [locale] },
        EmailTemplateTooLong = 29016 { kind: Validation, required: [max] },
        DuplicateEmailLocale = 29017 { kind: Validation, required: [locale] },
    }
}
