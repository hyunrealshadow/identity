//! Shared Relay-style keyset pagination primitives and boundary validation.

/// Default Relay connection page size when neither `first` nor `last` is supplied.
pub const DEFAULT_PAGE_SIZE: usize = 20;

/// Maximum Relay connection page size accepted across GraphQL and application queries.
pub const MAX_PAGE_SIZE: usize = 100;

/// Traversal direction for a Relay keyset query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageDirection {
    Forward,
    Backward,
}

impl PageDirection {
    /// Effective SQL sort direction for a query given the natural order direction
    /// (`default_descending`) and the traversal direction.
    #[must_use]
    pub const fn order_is_descending(self, default_descending: bool) -> bool {
        match self {
            Self::Forward => default_descending,
            Self::Backward => !default_descending,
        }
    }

    /// Compute `(has_previous_page, has_next_page)` from keyset over-fetch (`has_more`)
    /// and supplied boundary cursors.
    #[must_use]
    pub const fn page_flags(
        self,
        has_more: bool,
        after_present: bool,
        before_present: bool,
    ) -> (bool, bool) {
        match self {
            Self::Forward => (after_present, has_more),
            Self::Backward => (has_more, before_present),
        }
    }
}

/// Unvalidated Relay connection arguments before boundary checks.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawPageArgs<'a> {
    pub first: Option<i64>,
    pub after: Option<&'a str>,
    pub last: Option<i64>,
    pub before: Option<&'a str>,
}

impl<'a> RawPageArgs<'a> {
    #[must_use]
    pub fn from_i32(
        first: Option<i32>,
        after: Option<&'a str>,
        last: Option<i32>,
        before: Option<&'a str>,
    ) -> Self {
        Self {
            first: first.map(i64::from),
            after,
            last: last.map(i64::from),
            before,
        }
    }

    #[must_use]
    pub fn from_u32(
        first: Option<u32>,
        after: Option<&'a str>,
        last: Option<u32>,
        before: Option<&'a str>,
    ) -> Self {
        Self {
            first: first.map(i64::from),
            after,
            last: last.map(i64::from),
            before,
        }
    }
}

/// Validated Relay pagination parameters ready for cursor decoding and query execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedPage<'a> {
    pub direction: PageDirection,
    pub limit: usize,
    pub after: Option<&'a str>,
    pub before: Option<&'a str>,
}

/// Domain validation failure for Relay pagination arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaginationError {
    /// Caller combined incompatible forward and backward pagination arguments.
    ConflictingArguments { both_sizes: bool },
    /// Caller supplied a page size outside `1..=max`.
    InvalidPageSize { field: &'static str, max: usize },
}

/// Validate Relay connection arguments consistently across adapters and services.
///
/// Rejects all incompatible argument pairs (`first`+`last`, `after`+`before`,
/// `first`+`before`, `last`+`after`) and bounds the active page size to `1..=max_size`.
pub fn validate_page_arguments(
    args: RawPageArgs<'_>,
    default_size: usize,
    max_size: usize,
) -> Result<ValidatedPage<'_>, PaginationError> {
    let both_sizes = args.first.is_some() && args.last.is_some();
    let conflict = both_sizes
        || (args.after.is_some() && args.before.is_some())
        || (args.first.is_some() && args.before.is_some())
        || (args.last.is_some() && args.after.is_some());
    if conflict {
        return Err(PaginationError::ConflictingArguments { both_sizes });
    }

    let backward = args.last.is_some() || (args.first.is_none() && args.before.is_some());
    let (direction, raw_size, field, after, before) = if backward {
        (
            PageDirection::Backward,
            args.last,
            "last",
            None,
            args.before,
        )
    } else {
        (
            PageDirection::Forward,
            args.first,
            "first",
            args.after,
            None,
        )
    };

    let max_i64 = i64::try_from(max_size).unwrap_or(i64::MAX);
    let limit = match raw_size {
        None => default_size.clamp(1, max_size),
        Some(value) if value < 1 || value > max_i64 => {
            return Err(PaginationError::InvalidPageSize {
                field,
                max: max_size,
            });
        }
        Some(value) => value as usize,
    };

    Ok(ValidatedPage {
        direction,
        limit,
        after,
        before,
    })
}

/// Truncate a `limit + 1` keyset fetch, restore connection order for backward
/// traversal, and compute `(has_previous_page, has_next_page)`.
#[must_use]
pub fn finalize_keyset_page<T>(
    direction: PageDirection,
    mut items: Vec<T>,
    limit: usize,
    after_present: bool,
    before_present: bool,
) -> (Vec<T>, bool, bool) {
    let has_more = items.len() > limit;
    items.truncate(limit);
    if direction == PageDirection::Backward {
        items.reverse();
    }
    let (has_previous_page, has_next_page) =
        direction.page_flags(has_more, after_present, before_present);
    (items, has_previous_page, has_next_page)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_every_incompatible_relay_argument_pair() {
        let cases = [
            RawPageArgs::from_i32(Some(10), None, Some(10), None),
            RawPageArgs::from_i32(None, Some("a"), None, Some("b")),
            RawPageArgs::from_i32(Some(10), None, None, Some("b")),
            RawPageArgs::from_i32(None, Some("a"), Some(10), None),
        ];
        for (index, args) in cases.into_iter().enumerate() {
            let err = validate_page_arguments(args, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE).unwrap_err();
            assert_eq!(
                err,
                PaginationError::ConflictingArguments {
                    both_sizes: index == 0,
                }
            );
        }
    }

    #[test]
    fn enforces_page_size_bounds_without_wraparound() {
        for bad in [-5_i64, 0, 101, i64::MIN, i64::MAX] {
            let forward_err = validate_page_arguments(
                RawPageArgs {
                    first: Some(bad),
                    ..Default::default()
                },
                DEFAULT_PAGE_SIZE,
                MAX_PAGE_SIZE,
            )
            .unwrap_err();
            assert_eq!(
                forward_err,
                PaginationError::InvalidPageSize {
                    field: "first",
                    max: MAX_PAGE_SIZE,
                }
            );

            let backward_err = validate_page_arguments(
                RawPageArgs {
                    last: Some(bad),
                    ..Default::default()
                },
                DEFAULT_PAGE_SIZE,
                MAX_PAGE_SIZE,
            )
            .unwrap_err();
            assert_eq!(
                backward_err,
                PaginationError::InvalidPageSize {
                    field: "last",
                    max: MAX_PAGE_SIZE,
                }
            );
        }

        let min_ok = validate_page_arguments(
            RawPageArgs::from_i32(Some(1), None, None, None),
            DEFAULT_PAGE_SIZE,
            MAX_PAGE_SIZE,
        )
        .unwrap();
        assert_eq!(min_ok.limit, 1);

        let max_ok = validate_page_arguments(
            RawPageArgs::from_i32(None, None, Some(100), Some("cur")),
            DEFAULT_PAGE_SIZE,
            MAX_PAGE_SIZE,
        )
        .unwrap();
        assert_eq!(max_ok.direction, PageDirection::Backward);
        assert_eq!(max_ok.limit, 100);
        assert_eq!(max_ok.before, Some("cur"));
    }

    #[test]
    fn resolves_default_direction_and_limit() {
        let default_forward =
            validate_page_arguments(RawPageArgs::default(), DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE)
                .unwrap();
        assert_eq!(
            default_forward,
            ValidatedPage {
                direction: PageDirection::Forward,
                limit: DEFAULT_PAGE_SIZE,
                after: None,
                before: None,
            }
        );

        let before_only = validate_page_arguments(
            RawPageArgs::from_i32(None, None, None, Some("b")),
            DEFAULT_PAGE_SIZE,
            MAX_PAGE_SIZE,
        )
        .unwrap();
        assert_eq!(
            before_only,
            ValidatedPage {
                direction: PageDirection::Backward,
                limit: DEFAULT_PAGE_SIZE,
                after: None,
                before: Some("b"),
            }
        );
    }

    #[test]
    fn finalize_keyset_page_truncates_reverses_and_computes_flags() {
        let (forward_items, prev, next) =
            finalize_keyset_page(PageDirection::Forward, vec![1, 2, 3], 2, false, false);
        assert_eq!(forward_items, vec![1, 2]);
        assert!(!prev);
        assert!(next);

        let (backward_items, prev, next) =
            finalize_keyset_page(PageDirection::Backward, vec![3, 2, 1], 2, false, true);
        assert_eq!(backward_items, vec![2, 3]);
        assert!(prev);
        assert!(next);
    }
}
