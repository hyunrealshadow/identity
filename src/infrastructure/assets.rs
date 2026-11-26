//! Locating files shipped in the repository `assets/` directory.

use std::path::PathBuf;

/// Resolve `relative` against the workspace when running from a checkout,
/// otherwise against the working directory of a deployed binary.
pub(crate) fn workspace_path(relative: &str) -> PathBuf {
    let compile_time_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    let path_to_check = relative
        .find('*')
        .map(|index| PathBuf::from(&relative[..index]))
        .and_then(|path| path.parent().map(PathBuf::from))
        .map(|path| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(path)
        })
        .unwrap_or_else(|| compile_time_path.clone());

    if path_to_check.exists() {
        return compile_time_path;
    }

    PathBuf::from(relative)
}
