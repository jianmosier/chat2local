//! One ordered owner of actual disk work. Dropping a caller never cancels publication.
use crate::{Error, Result};
use chat2local_native_store::{Document, Store};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Notify, mpsc, oneshot};
type Work = Box<dyn FnOnce(&Store) + Send>;
pub struct Persistence {
    #[cfg(feature = "fixture")]
    point: &'static str,
    sender: mpsc::Sender<Work>,
    pending: Arc<AtomicUsize>,
    drained: Arc<Notify>,
    #[cfg(feature = "fixture")]
    hooks: Arc<crate::fixture::Hooks>,
}
impl Persistence {
    pub fn new(
        store: Arc<Store>,
        #[cfg(feature = "fixture")] hooks: Arc<crate::fixture::Hooks>,
    ) -> Arc<Self> {
        Self::lane(
            store,
            #[cfg(feature = "fixture")]
            hooks,
            "save",
        )
    }
    pub fn lane(
        store: Arc<Store>,
        #[cfg(feature = "fixture")] hooks: Arc<crate::fixture::Hooks>,
        _point: &'static str,
    ) -> Arc<Self> {
        #[cfg(feature = "fixture")]
        let point = _point;
        // Normal business has one executing write; recovery owns24 reserved slots.
        let (sender, mut receive) = mpsc::channel::<Work>(32);
        let pending = Arc::new(AtomicUsize::new(0));
        let drained = Arc::new(Notify::new());
        let p = pending.clone();
        let d = drained.clone();
        tokio::task::spawn_blocking(move || {
            while let Some(work) = receive.blocking_recv() {
                work(&store);
                p.fetch_sub(1, Ordering::SeqCst);
                d.notify_one();
            }
        });
        Arc::new(Self {
            #[cfg(feature = "fixture")]
            point,
            sender,
            pending,
            drained,
            #[cfg(feature = "fixture")]
            hooks,
        })
    }
    pub fn submit<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Store) -> Result<T> + Send + 'static,
    ) -> Result<oneshot::Receiver<Result<T>>> {
        let (reply, receive) = oneshot::channel();
        self.pending.fetch_add(1, Ordering::SeqCst);
        #[cfg(feature = "fixture")]
        let hooks = self.hooks.clone();
        #[cfg(feature = "fixture")]
        let point = self.point;
        let task = Box::new(move |store: &Store| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                #[cfg(feature = "fixture")]
                {
                    hooks.wait(point);
                    hooks.check(point)?;
                }
                work(store)
            }))
            .unwrap_or_else(|_| {
                Err(Error::new(
                    503,
                    "Persistence worker failed; completion is not confirmed.",
                ))
            });
            let _ = reply.send(result);
        });
        if self.sender.try_send(task).is_err() {
            self.pending.fetch_sub(1, Ordering::SeqCst);
            return Err(Error::new(
                503,
                "EPERSISTENCE: Persistence capacity unavailable; restriction is not confirmed.",
            ));
        }
        Ok(receive)
    }
    pub fn config(&self, config: Document) -> Result<oneshot::Receiver<Result<()>>> {
        self.submit(move |store| {
            store.save_config(&config)?;
            Ok(())
        })
    }
    pub fn pending(&self) -> usize {
        self.pending.load(Ordering::SeqCst)
    }
    pub async fn drain(&self) {
        while self.pending() != 0 {
            self.drained.notified().await;
        }
    }
}
pub async fn confirmed<T>(receive: oneshot::Receiver<Result<T>>, bounded: bool) -> Result<T> {
    let receive = async {
        receive
            .await
            .map_err(|_| Error::new(503, "EPERSISTENCE: Completion unavailable."))?
    };
    if bounded {
        tokio::time::timeout(std::time::Duration::from_secs(1), receive)
            .await
            .map_err(|_| {
                Error::new(
                    503,
                    "EPERSISTENCE: Persistence remains pending; ownership is retained.",
                )
            })?
    } else {
        receive.await
    }
}
