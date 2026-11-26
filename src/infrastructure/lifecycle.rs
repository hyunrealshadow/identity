use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::watch;

use crate::database::install_lock::InstallLockGuard;

#[derive(Clone)]
pub struct AppLifecycle {
    shutdown_requested: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
    install_lock: Arc<Mutex<Option<InstallLockGuard>>>,
}

impl Default for AppLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl AppLifecycle {
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
            install_lock: Arc::new(Mutex::new(None)),
        }
    }

    pub fn hold_install_lock(&self, guard: Option<InstallLockGuard>) {
        if let Ok(mut slot) = self.install_lock.lock() {
            *slot = guard;
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);
    }

    pub fn subscribe_shutdown(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    #[must_use]
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }
}

pub async fn wait_for_shutdown(lifecycle: Arc<AppLifecycle>) {
    if lifecycle.shutdown_requested() {
        return;
    }

    let mut rx = lifecycle.subscribe_shutdown();
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            break;
        }
    }
}
