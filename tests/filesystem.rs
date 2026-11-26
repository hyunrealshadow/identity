//! Filesystem integration for runtime assets, TLS material, and workload credentials.
#[path = "filesystem/assets.rs"]
mod assets;
#[path = "filesystem/tls.rs"]
mod tls;
#[path = "filesystem/workload.rs"]
mod workload;

#[path = "support/temp_dir.rs"]
mod temp_dir;
