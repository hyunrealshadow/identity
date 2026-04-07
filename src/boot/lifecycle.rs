use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::watch;

#[derive(Clone)]
pub struct AppLifecycle {
    shutdown_requested: Arc<AtomicBool>,
    shutdown_tx: watch::Sender<bool>,
}

impl AppLifecycle {
    pub fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            shutdown_tx,
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
