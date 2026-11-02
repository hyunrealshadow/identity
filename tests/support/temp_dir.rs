use std::{
    fs,
    ops::Deref,
    path::{Path, PathBuf},
};

pub struct TempDir {
    path: PathBuf,
    base: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        assert!(
            label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        );
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .unwrap();
        let base = workspace.join(".data/integration-tests");
        fs::create_dir_all(&base).unwrap();
        let base = base.canonicalize().unwrap();
        assert!(base.starts_with(&workspace));
        let path = base.join(format!("{label}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&path).unwrap();
        let path = path.canonicalize().unwrap();
        assert_eq!(path.parent(), Some(base.as_path()));
        Self { path, base }
    }
}

impl Deref for TempDir {
    type Target = Path;
    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Ok(path) = self.path.canonicalize()
            && path.parent() == Some(self.base.as_path())
        {
            let _ = fs::remove_dir_all(path);
        }
    }
}
