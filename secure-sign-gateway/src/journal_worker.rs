//! One bounded storage lane. No redb transaction runs on a Tokio worker.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, oneshot, watch};
use tonic::Status;

use crate::AntiEquivocationJournal;

const QUEUE_CAPACITY: usize = 64;
type Job = Box<dyn FnOnce(&AntiEquivocationJournal) + Send>;

#[derive(Default)]
pub(crate) struct Metrics {
    pub(crate) completed: AtomicU64,
    pub(crate) commit_failures: AtomicU64,
    pub(crate) rejected: AtomicU64,
    pub(crate) queue_wait_us: AtomicU64,
    pub(crate) operation_us: AtomicU64,
}

#[derive(Clone)]
pub(crate) struct JournalWorker {
    sender: mpsc::Sender<Job>,
    pub(crate) metrics: Arc<Metrics>,
    stopped: watch::Receiver<bool>,
}

impl JournalWorker {
    pub(crate) fn start(journal: AntiEquivocationJournal) -> Result<Self, String> {
        Self::start_with_capacity(journal, QUEUE_CAPACITY)
    }

    fn start_with_capacity(
        journal: AntiEquivocationJournal,
        capacity: usize,
    ) -> Result<Self, String> {
        let (sender, mut receiver) = mpsc::channel::<Job>(capacity);
        let metrics = Arc::new(Metrics::default());
        let (stopped_tx, stopped) = watch::channel(false);
        std::thread::Builder::new()
            .name("signing-journal".into())
            .spawn(move || {
                while let Some(job) = receiver.blocking_recv() {
                    job(&journal);
                }
                drop(journal);
                let _ = stopped_tx.send(true);
            })
            .map_err(|err| format!("start journal storage worker: {err}"))?;
        Ok(Self {
            sender,
            metrics,
            stopped,
        })
    }

    pub(crate) fn is_stopped(&self) -> bool {
        *self.stopped.borrow() || self.sender.is_closed()
    }

    #[cfg(test)]
    pub(crate) fn stopped_signal(&self) -> watch::Receiver<bool> {
        self.stopped.clone()
    }

    pub(crate) async fn run<R, F>(
        &self,
        operation: &'static str,
        deadline: Instant,
        apply: F,
    ) -> Result<R, Status>
    where
        R: Send + 'static,
        F: FnOnce(&AntiEquivocationJournal) -> Result<R, Status> + Send + 'static,
    {
        let queued_at = Instant::now();
        if queued_at >= deadline {
            return Err(Status::deadline_exceeded(
                "journal admission deadline exceeded",
            ));
        }
        let (reply, receiver) = oneshot::channel();
        let metrics = Arc::clone(&self.metrics);
        let job = Box::new(move |journal: &AntiEquivocationJournal| {
            let start = Instant::now();
            if start >= deadline || reply.is_closed() {
                let _ = reply.send(Err(Status::deadline_exceeded(
                    "journal queue deadline exceeded",
                )));
                return;
            }
            journal.cleanup_rows.store(0, Ordering::Relaxed);
            let result = apply(journal);
            let wait = start.duration_since(queued_at).as_micros() as u64;
            let elapsed = start.elapsed().as_micros() as u64;
            metrics.queue_wait_us.fetch_add(wait, Ordering::Relaxed);
            metrics.operation_us.fetch_add(elapsed, Ordering::Relaxed);
            metrics.completed.fetch_add(1, Ordering::Relaxed);
            eprintln!("signing_journal operation={operation} queue_wait_us={wait} duration_us={elapsed} replay_entries={} cleanup_rows={} ok={}",
                journal.replay_entries.load(Ordering::Relaxed), journal.cleanup_rows.load(Ordering::Relaxed), result.is_ok());
            // A timeout cannot cancel an in-progress disk commit. Keep its durable
            // result; the caller reports unknown and a same-digest retry reads it.
            let _ = reply.send(result);
        });
        self.sender.try_send(job).map_err(|err| {
            self.metrics.rejected.fetch_add(1, Ordering::Relaxed);
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    Status::resource_exhausted("journal queue full")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    Status::unavailable("journal worker stopped")
                }
            }
        })?;
        tokio::time::timeout_at(deadline.into(), receiver)
            .await
            .map_err(|_| Status::deadline_exceeded("journal operation deadline exceeded"))?
            .map_err(|_| Status::unavailable("journal worker stopped before reply"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn storage_queue_is_bounded_and_expired_jobs_do_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let journal =
            AntiEquivocationJournal::open(&dir.path().join("j.redb"), &dir.path().join("j.log"))
                .unwrap();
        let worker = JournalWorker::start_with_capacity(journal, 1).unwrap();
        let first = worker.clone();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let running = tokio::spawn(async move {
            first
                .run(
                    "slow",
                    Instant::now() + std::time::Duration::from_secs(2),
                    move |_| {
                        let _ = started_tx.send(());
                        release_rx
                            .recv_timeout(std::time::Duration::from_secs(2))
                            .unwrap();
                        Ok(())
                    },
                )
                .await
        });
        started_rx.await.unwrap();
        let wrote = Arc::new(AtomicU64::new(0));
        let queued_worker = worker.clone();
        let side_effect = Arc::clone(&wrote);
        let queued = tokio::spawn(async move {
            queued_worker
                .run(
                    "expired",
                    Instant::now() + std::time::Duration::from_millis(40),
                    move |_| {
                        side_effect.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .await
        });
        for _ in 0..100 {
            if worker.sender.capacity() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(worker.sender.capacity(), 0);
        assert_eq!(
            worker
                .run(
                    "overflow",
                    Instant::now() + std::time::Duration::from_secs(1),
                    |_| Ok(())
                )
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            queued.await.unwrap().unwrap_err().code(),
            tonic::Code::DeadlineExceeded
        );
        release_tx.send(()).unwrap();
        running.await.unwrap().unwrap();
        worker
            .run(
                "barrier",
                Instant::now() + std::time::Duration::from_secs(1),
                |_| Ok(()),
            )
            .await
            .unwrap();
        assert_eq!(wrote.load(Ordering::SeqCst), 0);
        assert_eq!(worker.metrics.rejected.load(Ordering::Relaxed), 1);
    }
}
