/*
A scoped worker borrows analysis input while the caller retains console control.
Separate progress and terminal channels prevent a busy display from losing the final result.
The component provides a worker contract only. L06.2 will connect terminal input and application tools.
*/
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::time::Duration;

/*
Each cooperative worker must check its Reporter between bounded work windows.
This shared limit prepares future analysis consumers without changing current tools.
*/
pub(crate) const WINDOW_BYTES: usize = 64 * 1024;

/*
Progress contains the finished byte count and the complete work size.
Construction clamps an excessive finished count so display callers receive a valid fraction.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) completed: u64,
    pub(crate) total: u64,
}

impl Progress {
    /*
    This constructor accepts all u64 boundary values, including a zero total.
    The returned count never exceeds the supplied total.
    */
    pub(crate) fn new(completed: u64, total: u64) -> Self {
        Self {
            completed: completed.min(total),
            total,
        }
    }
}

/*
A source identity and revision travel with the result.
The caller compares this stamp with the current editor before using the result.
Distinct identities separate different buffers. Revisions separate byte states within one buffer.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SourceStamp {
    identity: u64,
    revision: u64,
}

impl SourceStamp {
    /*
    Editor owns stamp creation and supplies both counter values.
    Analysis keeps both values opaque and compares the complete stamp.
    */
    pub(crate) fn new(identity: u64, revision: u64) -> Self {
        Self { identity, revision }
    }
}

/*
Outcome separates one complete payload from cooperative cancellation.
Workers must not put partial data in the Completed variant.
*/
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome<T> {
    Completed(T),
    Canceled,
}

/*
Terminal carries one stamped worker result on the reliable result channel.
The inner String keeps an analysis error separate from callback and worker I/O errors.
*/
#[derive(Debug)]
pub(crate) struct Terminal<T> {
    pub(crate) stamp: SourceStamp,
    pub(crate) result: Result<Outcome<T>, String>,
}

/*
Acceptance checks source identity before it exposes a worker result.
Matching results retain the original Completed, Canceled, or analysis-error layer.
*/
impl<T> Terminal<T> {
    pub(crate) fn accept(self, current: SourceStamp) -> io::Result<Result<Outcome<T>, String>> {
        if self.stamp != current {
            return Err(io::Error::other(
                "Analysis result is stale because the buffer changed.",
            ));
        }
        Ok(self.result)
    }
}

/*
Reporter gives the worker one nonblocking progress output and one shared cancellation flag.
Dropping the receiver also tells the worker to stop at its next report boundary.
*/
pub(crate) struct Reporter {
    progress: SyncSender<Progress>,
    cancel: Arc<AtomicBool>,
}

/*
Progress is advisory, so a full one-slot channel can drop an update.
Cancellation and channel disconnection stop work without blocking the worker on display speed.
*/
impl Reporter {
    /*
    The worker calls this method between bounded work units.
    The return value requests termination after cancellation or receiver disconnection.
    */
    pub(crate) fn progress(&self, progress: Progress) -> bool {
        if self.cancel.load(Ordering::Acquire) {
            return false;
        }
        match self.progress.try_send(progress) {
            Ok(()) | Err(TrySendError::Full(_)) => !self.cancel.load(Ordering::Acquire),
            Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

/*
The scope keeps borrowed input alive until the worker joins.
A separate terminal channel carries completion, cancellation, or an analysis error exactly once.
Cancellation remains cooperative and cannot preempt blocking I/O or an uncooperative closure.
*/
pub(crate) fn run<T, F, U, C>(
    stamp: SourceStamp,
    work: F,
    mut update: U,
    mut cancel: C,
) -> io::Result<Terminal<T>>
where
    T: Send,
    F: FnOnce(Reporter) -> Result<Outcome<T>, String> + Send,
    U: FnMut(Progress) -> io::Result<()>,
    C: FnMut() -> io::Result<bool>,
{
    let (progress_send, progress_receive) = mpsc::sync_channel(1);
    let (terminal_send, terminal_receive) = mpsc::sync_channel(1);
    let canceled = Arc::new(AtomicBool::new(false));

    std::thread::scope(|scope| {
        let worker_cancel = Arc::clone(&canceled);
        let worker = std::thread::Builder::new()
            .name("hview-analysis".into())
            .spawn_scoped(scope, move || {
                let reporter = Reporter {
                    progress: progress_send,
                    cancel: worker_cancel,
                };
                let result = work(reporter);
                terminal_send.send(Terminal { stamp, result })
            })?;

        /*
        Check terminal delivery before the cancellation callback.
        Stop cancellation polling after the callback reports cancellation.
        Preserve callback errors while the worker observes cancellation and joins.
        */
        let mut callback_error = None;
        let mut cancel_observed = false;
        let terminal = loop {
            match terminal_receive.try_recv() {
                Ok(terminal) => break Some(terminal),
                Err(mpsc::TryRecvError::Disconnected) => break None,
                Err(mpsc::TryRecvError::Empty) => {}
            }

            if callback_error.is_none() && !cancel_observed {
                match cancel() {
                    Ok(true) => {
                        cancel_observed = true;
                        canceled.store(true, Ordering::Release);
                    }
                    Ok(false) => {}
                    Err(error) => {
                        canceled.store(true, Ordering::Release);
                        callback_error = Some(error);
                    }
                }
            }

            match progress_receive.recv_timeout(Duration::from_millis(20)) {
                Ok(progress) if callback_error.is_none() && !cancel_observed => {
                    if let Err(error) = update(progress) {
                        canceled.store(true, Ordering::Release);
                        callback_error = Some(error);
                    }
                }
                Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    match terminal_receive.recv_timeout(Duration::from_millis(20)) {
                        Ok(terminal) => break Some(terminal),
                        Err(mpsc::RecvTimeoutError::Disconnected) => break None,
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                    }
                }
            }
        };

        /*
        Join before resolving the result so no worker outlives the borrowed source.
        An observed cancellation overrides a racing completed result, while callback failures remain I/O errors.
        */
        let joined = worker.join();
        if let Some(error) = callback_error {
            return Err(error);
        }
        match (joined, terminal) {
            (Err(_), _) => Err(io::Error::other(
                "The analysis worker stopped unexpectedly.",
            )),
            (Ok(Err(_)), _) => Err(io::Error::other(
                "The analysis worker could not send its result.",
            )),
            (Ok(Ok(())), Some(mut terminal)) => {
                if cancel_observed && matches!(terminal.result, Ok(Outcome::Completed(_))) {
                    terminal.result = Ok(Outcome::Canceled);
                }
                Ok(terminal)
            }
            (Ok(Ok(())), None) => Err(io::Error::other(
                "The analysis worker did not send a result.",
            )),
        }
    })
}

/*
Channel-controlled tests exercise worker order, cancellation, errors, and stamp acceptance.
Each synchronization point uses channels instead of elapsed-time assumptions.
*/
#[cfg(test)]
mod tests {
    use super::*;
    use crate::editor::{Editor, Mode};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    const TEST_WAIT: Duration = Duration::from_secs(2);

    /*
    DropMarker proves that run joins a worker before it returns any result or callback error.
    The shared flag lets each error test inspect lifetime completion after run returns.
    */
    struct DropMarker(Arc<AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    /*
    Progress construction must accept zero and maximum totals without overflow.
    The completed count stays inside the reported work range.
    */
    #[test]
    fn progress_clamps_all_u64_boundaries() {
        assert_eq!(Progress::new(1, 0), Progress::new(0, 0));
        assert_eq!(
            Progress::new(u64::MAX, u64::MAX - 1),
            Progress {
                completed: u64::MAX - 1,
                total: u64::MAX - 1,
            }
        );
        assert_eq!(
            Progress::new(u64::MAX, u64::MAX),
            Progress {
                completed: u64::MAX,
                total: u64::MAX,
            }
        );
        assert_eq!(WINDOW_BYTES, 64 * 1024);
    }

    /*
    A scoped worker can borrow stable caller bytes and complete without one progress update.
    Stamp acceptance returns the original complete payload after the worker joins.
    */
    #[test]
    fn scoped_worker_borrows_data_and_can_complete_without_progress() {
        let data = [1u8, 2, 3, 4];
        let stamp = SourceStamp::new(7, 9);
        let terminal = run(
            stamp,
            |_| {
                Ok(Outcome::Completed(
                    data.iter().map(|byte| u64::from(*byte)).sum::<u64>(),
                ))
            },
            |_| panic!("A completed task did not report progress."),
            || Ok(false),
        )
        .unwrap();
        assert_eq!(terminal.stamp, stamp);
        assert_eq!(
            terminal.accept(stamp).unwrap().unwrap(),
            Outcome::Completed(10)
        );
    }

    /*
    A full advisory channel drops one update without blocking terminal completion.
    Separate direct Reporter checks cover cancellation and receiver disconnection.
    */
    #[test]
    fn progress_pressure_and_stop_signals_do_not_block_the_worker() {
        let (ready_send, ready_receive) = mpsc::channel();
        let (finish_send, finish_receive) = mpsc::channel();
        let updates = Arc::new(Mutex::new(Vec::new()));
        let shown = Arc::clone(&updates);
        let terminal = run(
            SourceStamp::new(1, 0),
            move |reporter| {
                assert!(reporter.progress(Progress::new(1, 4)));
                assert!(reporter.progress(Progress::new(2, 4)));
                ready_send.send(()).unwrap();
                finish_receive.recv_timeout(TEST_WAIT).unwrap();
                Ok(Outcome::Completed(4))
            },
            move |progress| {
                shown.lock().unwrap().push(progress);
                finish_send.send(()).unwrap();
                Ok(())
            },
            {
                let mut ready = false;
                move || {
                    if !ready {
                        ready_receive.recv_timeout(TEST_WAIT).unwrap();
                        ready = true;
                    }
                    Ok(false)
                }
            },
        )
        .unwrap();
        assert_eq!(terminal.result, Ok(Outcome::Completed(4)));
        assert_eq!(updates.lock().unwrap().as_slice(), [Progress::new(1, 4)]);

        /*
        These direct Reporter cases isolate both reasons that request worker termination.
        Neither case needs a running scoped thread to check the nonblocking return value.
        */
        let (sender, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let disconnected = Reporter {
            progress: sender,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        assert!(!disconnected.progress(Progress::new(1, 1)));

        let (sender, _receiver) = mpsc::sync_channel(1);
        let canceled = Reporter {
            progress: sender,
            cancel: Arc::new(AtomicBool::new(true)),
        };
        assert!(!canceled.progress(Progress::new(1, 1)));
    }

    /*
    Observed cancellation suppresses queued progress and stops later input polling.
    The worker returns no partial payload after Reporter observes the cancellation flag.
    */
    #[test]
    fn cancellation_stops_callbacks_and_returns_no_partial_payload() {
        let (ready_send, ready_receive) = mpsc::channel();
        let cancel_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&cancel_calls);
        let terminal = run(
            SourceStamp::new(4, 0),
            move |reporter| {
                assert!(reporter.progress(Progress::new(1, 100)));
                ready_send.send(()).unwrap();
                let deadline = Instant::now() + TEST_WAIT;
                while reporter.progress(Progress::new(2, 100)) {
                    assert!(
                        Instant::now() < deadline,
                        "The worker did not observe cancellation."
                    );
                    std::thread::yield_now();
                }
                Ok(Outcome::<Vec<u8>>::Canceled)
            },
            |_| panic!("Queued progress must not display after cancellation."),
            move || {
                let call = calls.fetch_add(1, Ordering::AcqRel);
                assert_eq!(call, 0, "Cancellation input was polled again.");
                ready_receive.recv_timeout(TEST_WAIT).unwrap();
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(terminal.result, Ok(Outcome::Canceled));
        assert_eq!(cancel_calls.load(Ordering::Acquire), 1);
    }

    /*
    This ordered race releases a complete worker result during the first cancellation poll.
    The already observed cancellation replaces the racing payload with Canceled.
    */
    #[test]
    fn observed_cancellation_wins_a_racing_complete_result() {
        let (ready_send, ready_receive) = mpsc::channel();
        let (go_send, go_receive) = mpsc::channel();
        let mut cancel_calls = 0;
        let terminal = run(
            SourceStamp::new(3, 0),
            move |_| {
                ready_send.send(()).unwrap();
                go_receive.recv_timeout(TEST_WAIT).unwrap();
                Ok(Outcome::Completed(7))
            },
            |_| Ok(()),
            move || {
                cancel_calls += 1;
                assert_eq!(cancel_calls, 1, "Cancellation input was polled again.");
                ready_receive.recv_timeout(TEST_WAIT).unwrap();
                go_send.send(()).unwrap();
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(terminal.result, Ok(Outcome::Canceled));

        /*
        Cancellation overrides a complete payload only.
        A racing analysis failure keeps its exact analysis-error layer.
        */
        let (ready_send, ready_receive) = mpsc::channel();
        let (go_send, go_receive) = mpsc::channel();
        let terminal = run::<(), _, _, _>(
            SourceStamp::new(3, 1),
            move |_| {
                ready_send.send(()).unwrap();
                go_receive.recv_timeout(TEST_WAIT).unwrap();
                Err("Late analysis failure".into())
            },
            |_| Ok(()),
            move || {
                ready_receive.recv_timeout(TEST_WAIT).unwrap();
                go_send.send(()).unwrap();
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(terminal.result, Err("Late analysis failure".into()));
    }

    /*
    The worker drops Reporter before it finishes and waits for a later cancellation poll.
    Bounded terminal polling keeps input available until the cooperative worker returns.
    */
    #[test]
    fn dropped_reporter_does_not_stop_later_cancellation_polling() {
        let (ready_send, ready_receive) = mpsc::channel();
        let (finish_send, finish_receive) = mpsc::channel();
        let mut cancel_calls = 0;
        let terminal = run(
            SourceStamp::new(5, 0),
            move |reporter| {
                drop(reporter);
                ready_send.send(()).unwrap();
                finish_receive.recv_timeout(TEST_WAIT).unwrap();
                Ok(Outcome::Completed(5))
            },
            |_| panic!("The worker dropped its progress channel."),
            move || {
                cancel_calls += 1;
                match cancel_calls {
                    1 => {
                        ready_receive.recv_timeout(TEST_WAIT).unwrap();
                        Ok(false)
                    }
                    2 => {
                        finish_send.send(()).unwrap();
                        Ok(true)
                    }
                    _ => panic!("Cancellation input was polled after cancellation."),
                }
            },
        )
        .unwrap();
        assert_eq!(terminal.result, Ok(Outcome::Canceled));
    }

    /*
    Worker, display, and input failures use their separate result layers.
    Each failure drops its worker marker before run returns to the caller.
    */
    #[test]
    fn worker_and_callback_errors_join_the_worker() {
        let stamp = SourceStamp::new(1, 0);

        /* The terminal result keeps the exact analysis error after the worker exits. */
        let analysis_marker = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&analysis_marker);
        let terminal = run(
            stamp,
            move |_| {
                let _drop = DropMarker(marker);
                Err::<Outcome<()>, _>("Analysis failed".into())
            },
            |_| Ok(()),
            || Ok(false),
        )
        .unwrap();
        assert_eq!(terminal.result, Err("Analysis failed".into()));
        assert!(analysis_marker.load(Ordering::Acquire));

        /* A panic becomes one clear I/O error after the scoped worker drops its state. */
        let panic_marker = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&panic_marker);
        let error = run::<(), _, _, _>(
            stamp,
            move |_| {
                let _drop = DropMarker(marker);
                panic!("test worker panic")
            },
            |_| Ok(()),
            || Ok(false),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "The analysis worker stopped unexpectedly."
        );
        assert!(panic_marker.load(Ordering::Acquire));

        /* A progress callback error requests cancellation and remains the returned I/O error. */
        let display_marker = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&display_marker);
        let error = run::<(), _, _, _>(
            stamp,
            move |reporter| {
                let _drop = DropMarker(marker);
                let deadline = Instant::now() + TEST_WAIT;
                while reporter.progress(Progress::new(1, 2)) {
                    assert!(
                        Instant::now() < deadline,
                        "The worker did not observe the display failure."
                    );
                    std::thread::yield_now();
                }
                Ok(Outcome::Canceled)
            },
            |_| Err(io::Error::other("Display failed")),
            || Ok(false),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "Display failed");
        assert!(display_marker.load(Ordering::Acquire));

        /* A cancellation callback error follows the same join rule and keeps its exact text. */
        let input_marker = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&input_marker);
        let (ready_send, ready_receive) = mpsc::channel();
        let error = run::<(), _, _, _>(
            stamp,
            move |reporter| {
                let _drop = DropMarker(marker);
                ready_send.send(()).unwrap();
                let deadline = Instant::now() + TEST_WAIT;
                while reporter.progress(Progress::new(1, 2)) {
                    assert!(
                        Instant::now() < deadline,
                        "The worker did not observe the input failure."
                    );
                    std::thread::yield_now();
                }
                Ok(Outcome::Canceled)
            },
            |_| Ok(()),
            move || {
                ready_receive.recv_timeout(TEST_WAIT).unwrap();
                Err(io::Error::other("Input failed"))
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "Input failed");
        assert!(input_marker.load(Ordering::Acquire));
    }

    /*
    Terminal acceptance exposes current results and rejects stale results before payload access.
    Mutations, history actions, cancellation, source adoption, and another editor supply stale stamps.
    */
    #[test]
    fn terminal_acceptance_rejects_each_changed_buffer_stamp() {
        /* This helper proves that stale payloads remain inaccessible at each mutation boundary. */
        fn assert_stale(stamp: SourceStamp, current: SourceStamp) {
            let terminal = Terminal {
                stamp,
                result: Ok(Outcome::Completed(9)),
            };
            assert_eq!(
                terminal.accept(current).unwrap_err().to_string(),
                "Analysis result is stale because the buffer changed."
            );
        }

        let mut editor = Editor::new(vec![0x12], Mode::Hex, 0);
        let stamp = editor.buffer_stamp();
        let current = Terminal {
            stamp,
            result: Ok(Outcome::Completed(4)),
        };
        assert_eq!(
            current.accept(editor.buffer_stamp()).unwrap().unwrap(),
            Outcome::Completed(4)
        );

        let canceled = Terminal::<u8> {
            stamp,
            result: Ok(Outcome::Canceled),
        };
        assert_eq!(
            canceled.accept(editor.buffer_stamp()).unwrap().unwrap(),
            Outcome::Canceled
        );
        let failed = Terminal::<u8> {
            stamp,
            result: Err("Analysis failed exactly".into()),
        };
        assert_eq!(
            failed.accept(editor.buffer_stamp()).unwrap(),
            Err("Analysis failed exactly".into())
        );

        /* A byte mutation and both history directions each invalidate the preceding stamp. */
        editor.toggle_edit().unwrap();
        editor.hex_digit('f').unwrap();
        assert_stale(stamp, editor.buffer_stamp());

        let before_undo = editor.buffer_stamp();
        assert!(editor.undo().unwrap());
        assert_stale(before_undo, editor.buffer_stamp());

        let before_redo = editor.buffer_stamp();
        assert!(editor.redo().unwrap());
        assert_stale(before_redo, editor.buffer_stamp());
        let before_cancel = editor.buffer_stamp();
        editor.cancel_edit();
        assert_stale(before_cancel, editor.buffer_stamp());

        /* Source adoption and another Editor identity reject results without a byte mutation. */
        let before_adoption = editor.buffer_stamp();
        editor.source_changed();
        assert_stale(before_adoption, editor.buffer_stamp());

        let other = Editor::new(vec![0x12], Mode::Hex, 0);
        assert_stale(editor.buffer_stamp(), other.buffer_stamp());
    }
}
