#[macro_export]
macro_rules! define_error_codes {
    (
        $(#[$enum_meta:meta])*
        pub enum $EnumName:ident $((module = $default_mod:literal))? {
            $(
                $(#[$variant_meta:meta])*
                $Variant:ident = $code:literal {
                    kind: $kind:ident
                    $(, required: [$($req:ident),+ $(,)?])?
                    $(, optional: [$($opt:ident),+ $(,)?])?
                    $(, module: $vmod:literal)?
                    $(,)?
                }
            ),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[repr(u32)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::EnumIter)]
        pub enum $EnumName {
            $(
                $(#[$variant_meta])*
                $Variant = $code,
            )*
        }

        impl $EnumName {
            /// Every error code variant defined in this module.
            pub const ALL: &'static [Self] = &[$(Self::$Variant),*];
        }

        impl crate::error::code::AppErrorCode for $EnumName {
            fn kind(self) -> crate::error::kind::ErrorKind {
                match self {
                    $(Self::$Variant => crate::error::kind::ErrorKind::$kind,)*
                }
            }

            fn code(self) -> u32 {
                self as u32
            }

            fn group(self) -> &'static str {
                stringify!($EnumName)
            }

            fn name(self) -> &'static str {
                match self {
                    $(Self::$Variant => stringify!($Variant),)*
                }
            }

            fn required_params(self) -> &'static [&'static str] {
                match self {
                    $(Self::$Variant => &[$($(stringify!($req)),+)?],)*
                }
            }

            fn optional_params(self) -> &'static [&'static str] {
                match self {
                    $(Self::$Variant => &[$($(stringify!($opt)),+)?],)*
                }
            }

            fn usage_module(self) -> Option<&'static str> {
                let default_module: Option<&'static str> =
                    define_error_codes!(@default_module $($default_mod)?);
                let _ = &default_module;
                match self {
                    $(
                        Self::$Variant => {
                            define_error_codes!(@variant_module default_module $(, $vmod)?)
                        }
                    )*
                }
            }
        }

        pub mod error {
            $(
                define_error_codes!(
                    @variant
                    [$(#[$variant_meta])*]
                    $EnumName,
                    $Variant,
                    [$($($req),+)?],
                    [$($($opt),+)?]
                );
            )*
        }
    };

    (@default_module) => {
        None
    };
    (@default_module $default_mod:literal) => {
        Some($default_mod)
    };
    (@variant_module $default_module:ident) => {
        $default_module
    };
    (@variant_module $default_module:ident, $vmod:literal) => {
        Some($vmod)
    };

    (@variant [$(#[$variant_meta:meta])*] $EnumName:ident, $Variant:ident, [], []) => {
        $(#[$variant_meta])*
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $Variant;

        impl $Variant {
            pub const CODE: super::$EnumName = super::$EnumName::$Variant;

            #[must_use]
            pub const fn new() -> Self {
                Self
            }

            #[must_use]
            pub fn into_error(self) -> crate::error::AppError {
                crate::error::AppError::from_parts(
                    Self::CODE,
                    crate::error::params::ErrorParams::new(),
                )
            }

            #[must_use]
            pub fn with_source(
                self,
                source: impl std::error::Error + Send + Sync + 'static,
            ) -> crate::error::AppError {
                self.into_error().with_source(source)
            }

            #[must_use]
            pub fn with_field(self, field: impl Into<String>) -> crate::error::AppError {
                self.into_error().with_field(field)
            }

            #[must_use]
            pub fn with_field_error(
                self,
                field: impl Into<String>,
                error: impl Into<crate::error::AppError>,
            ) -> crate::error::AppError {
                self.into_error().with_field_error(field, error)
            }

            pub fn map_source<E: std::error::Error + Send + Sync + 'static>()
            -> impl FnOnce(E) -> crate::error::AppError {
                move |source| Self.with_source(source)
            }
        }

        impl From<$Variant> for crate::error::AppError {
            fn from(value: $Variant) -> Self {
                value.into_error()
            }
        }
    };

    (@variant [$(#[$variant_meta:meta])*] $EnumName:ident, $Variant:ident, [], [$($opt:ident),+]) => {
        $(#[$variant_meta])*
        #[derive(Debug, Clone, Default)]
        pub struct $Variant {
            params: crate::error::params::ErrorParams,
        }

        impl $Variant {
            pub const CODE: super::$EnumName = super::$EnumName::$Variant;

            #[must_use]
            pub fn new() -> Self {
                Self::default()
            }

            $(
                #[must_use]
                pub fn $opt(mut self, value: impl std::fmt::Display) -> Self {
                    self.params = self.params.insert(stringify!($opt), value.to_string());
                    self
                }
            )+

            #[must_use]
            pub fn into_error(self) -> crate::error::AppError {
                crate::error::AppError::from_parts(Self::CODE, self.params)
            }

            #[must_use]
            pub fn with_source(
                self,
                source: impl std::error::Error + Send + Sync + 'static,
            ) -> crate::error::AppError {
                self.into_error().with_source(source)
            }

            #[must_use]
            pub fn with_field(self, field: impl Into<String>) -> crate::error::AppError {
                self.into_error().with_field(field)
            }

            #[must_use]
            pub fn with_field_error(
                self,
                field: impl Into<String>,
                error: impl Into<crate::error::AppError>,
            ) -> crate::error::AppError {
                self.into_error().with_field_error(field, error)
            }

            pub fn map_source<E: std::error::Error + Send + Sync + 'static>()
            -> impl FnOnce(E) -> crate::error::AppError {
                move |source| Self::new().with_source(source)
            }
        }

        impl From<$Variant> for crate::error::AppError {
            fn from(value: $Variant) -> Self {
                value.into_error()
            }
        }
    };

    (@variant [$(#[$variant_meta:meta])*] $EnumName:ident, $Variant:ident, [$($req:ident),+], [$($opt:ident),*]) => {
        $(#[$variant_meta])*
        #[derive(Debug, Clone)]
        pub struct $Variant {
            params: crate::error::params::ErrorParams,
        }

        impl $Variant {
            pub const CODE: super::$EnumName = super::$EnumName::$Variant;

            #[must_use]
            #[allow(unused_mut)]
            pub fn new($($req: impl std::fmt::Display),+) -> Self {
                let mut params = crate::error::params::ErrorParams::new();
                $(
                    params = params.insert(stringify!($req), $req.to_string());
                )+
                Self { params }
            }

            $(
                #[must_use]
                pub fn $opt(mut self, value: impl std::fmt::Display) -> Self {
                    self.params = self.params.insert(stringify!($opt), value.to_string());
                    self
                }
            )*

            #[must_use]
            pub fn into_error(self) -> crate::error::AppError {
                crate::error::AppError::from_parts(Self::CODE, self.params)
            }

            #[must_use]
            pub fn with_source(
                self,
                source: impl std::error::Error + Send + Sync + 'static,
            ) -> crate::error::AppError {
                self.into_error().with_source(source)
            }

            #[must_use]
            pub fn with_field(self, field: impl Into<String>) -> crate::error::AppError {
                self.into_error().with_field(field)
            }

            #[must_use]
            pub fn with_field_error(
                self,
                field: impl Into<String>,
                error: impl Into<crate::error::AppError>,
            ) -> crate::error::AppError {
                self.into_error().with_field_error(field, error)
            }
        }

        impl From<$Variant> for crate::error::AppError {
            fn from(value: $Variant) -> Self {
                value.into_error()
            }
        }
    };
}

#[macro_export]
macro_rules! define_error_code_registry {
    (
        $(
            $Variant:ident($path:path) in $range:expr
        ),* $(,)?
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ErrorCode {
            $($Variant($path),)*
        }

        $(
            impl From<$path> for ErrorCode {
                fn from(value: $path) -> Self {
                    Self::$Variant(value)
                }
            }
        )*

        impl crate::error::code::AppErrorCode for ErrorCode {
            fn kind(self) -> crate::error::kind::ErrorKind {
                match self {
                    $(Self::$Variant(code) => code.kind(),)*
                }
            }

            fn code(self) -> u32 {
                match self {
                    $(Self::$Variant(code) => code.code(),)*
                }
            }

            fn group(self) -> &'static str {
                match self {
                    $(Self::$Variant(code) => code.group(),)*
                }
            }

            fn name(self) -> &'static str {
                match self {
                    $(Self::$Variant(code) => code.name(),)*
                }
            }

            fn required_params(self) -> &'static [&'static str] {
                match self {
                    $(Self::$Variant(code) => code.required_params(),)*
                }
            }

            fn optional_params(self) -> &'static [&'static str] {
                match self {
                    $(Self::$Variant(code) => code.optional_params(),)*
                }
            }

            fn usage_module(self) -> Option<&'static str> {
                match self {
                    $(Self::$Variant(code) => code.usage_module(),)*
                }
            }
        }

        impl ErrorCode {
            /// Every error code registered across all domain/application modules.
            #[must_use]
            pub fn all() -> Vec<Self> {
                use strum::IntoEnumIterator as _;
                let mut all = Vec::new();
                $(
                    all.extend(<$path>::iter().map(Self::$Variant));
                )*
                all
            }

            /// Reserved numeric range for this error code's owning module.
            #[must_use]
            pub const fn range(self) -> std::ops::RangeInclusive<u32> {
                match self {
                    $(Self::$Variant(_) => $range,)*
                }
            }
        }
    };
}
