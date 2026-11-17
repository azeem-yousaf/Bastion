//! Bounds on what the server can make this client queue.
//!
//! A server request costs a few bytes on the wire but is answered with up to megabytes (a file
//! range, a rendered image). Requests arrive on the session thread and answers leave through
//! the session's command queue, and neither end applies backpressure, so both are bounded here:
//!
//! * **Requests** waiting for the worker are counted ([`Shared::admit`]). Past
//!   [`MAX_QUEUED_REQUESTS`] a request is only queued to be refused; past twice that it is
//!   dropped, so the queue cannot grow with the number of PDUs the server sends.
//! * **Response bytes** handed to the session but not yet written to the socket are counted
//!   (`Budget`). While more than [`RESPONSE_BUDGET_BYTES`] are outstanding, further data
//!   requests wait (a few) or are refused (the rest).
//!
//! The crate cannot see the socket. The session reports written responses through
//! [`FlowControl::track`]; until it has done so once, the budget assumes the queue drains at
//! [`UNTRACKED_DRAIN_BYTES_PER_SEC`], which paces a flood without failing a legitimate transfer.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use ironrdp_cliprdr::backend::ClipboardMessage;

/// Server requests queued for the worker before new ones are refused.
pub(crate) const MAX_QUEUED_REQUESTS: usize = 64;
/// Response payload that may sit unwritten before further data requests wait or are refused.
/// The peak is this plus one response (a file range of at most 8 MiB, or one clipboard format).
pub(crate) const RESPONSE_BUDGET_BYTES: usize = 32 * 1024 * 1024;
/// Assumed drain rate while the session does not report writes.
pub(crate) const UNTRACKED_DRAIN_BYTES_PER_SEC: usize = 16 * 1024 * 1024;

/// What the backend should do with a server request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    /// Queue it for the worker.
    Serve,
    /// Queue only a refusal (answered with a failure response).
    Refuse,
    /// Queue nothing.
    Drop,
}

#[derive(Debug, Default)]
pub(crate) struct Shared {
    queued_requests: AtomicUsize,
    outstanding_bytes: AtomicUsize,
    tracked: AtomicBool,
}

fn saturating_sub(value: &AtomicUsize, n: usize) {
    let mut current = value.load(Ordering::Acquire);
    while let Err(seen) =
        value.compare_exchange_weak(current, current.saturating_sub(n), Ordering::AcqRel, Ordering::Acquire)
    {
        current = seen;
    }
}

impl Shared {
    /// Counts a server request about to be queued. Every [`Admission::Serve`] and
    /// [`Admission::Refuse`] must be matched by one [`Shared::request_handled`].
    pub(crate) fn admit(&self) -> Admission {
        let queued = self.queued_requests.fetch_add(1, Ordering::AcqRel);
        if queued < MAX_QUEUED_REQUESTS {
            Admission::Serve
        } else if queued < MAX_QUEUED_REQUESTS * 2 {
            Admission::Refuse
        } else {
            saturating_sub(&self.queued_requests, 1);
            Admission::Drop
        }
    }

    pub(crate) fn request_handled(&self) {
        saturating_sub(&self.queued_requests, 1);
    }

    #[cfg(test)]
    pub(crate) fn queued_requests(&self) -> usize {
        self.queued_requests.load(Ordering::Acquire)
    }

    fn release(&self, bytes: usize) {
        self.tracked.store(true, Ordering::Release);
        saturating_sub(&self.outstanding_bytes, bytes);
    }
}

/// Handle through which the session reports clipboard responses it has written, so the worker
/// knows how much response data is still queued.
///
/// Take a guard for every [`ClipboardMessage`] as soon as it is dequeued and keep it until the
/// resulting frame was written (or the message was discarded):
///
/// ```ignore
/// Command::Clipboard(msg) => {
///     let _sent = flow.track(&msg);
///     // ... encode, write to the socket ...
/// }
/// ```
#[derive(Debug, Clone, Default)]
pub struct FlowControl(Arc<Shared>);

impl FlowControl {
    /// Payload bytes `message` holds against the response budget (0 unless it carries data).
    pub fn cost(message: &ClipboardMessage) -> usize {
        match message {
            ClipboardMessage::SendFormatData(response) => response.data().len(),
            ClipboardMessage::SendFileContentsResponse(response) => response.data().len(),
            _ => 0,
        }
    }

    /// Returns a guard that releases `message`'s share of the budget when dropped.
    #[must_use = "the budget is released when the guard is dropped; hold it until the write finished"]
    pub fn track(&self, message: &ClipboardMessage) -> SentGuard {
        // Mark the budget as tracked even for messages that cost nothing.
        self.0.tracked.store(true, Ordering::Release);
        SentGuard { shared: Arc::clone(&self.0), bytes: Self::cost(message) }
    }

    /// Releases `bytes` of the budget directly (for callers that cannot hold a guard).
    pub fn written(&self, bytes: usize) {
        self.0.release(bytes);
    }

    pub(crate) fn shared(&self) -> Arc<Shared> {
        Arc::clone(&self.0)
    }
}

/// See [`FlowControl::track`].
#[derive(Debug)]
pub struct SentGuard {
    shared: Arc<Shared>,
    bytes: usize,
}

impl Drop for SentGuard {
    fn drop(&mut self) {
        self.shared.release(self.bytes);
    }
}

/// The worker's view of the response budget.
#[derive(Debug)]
pub(crate) struct Budget {
    shared: Arc<Shared>,
    drained_until: Instant,
}

impl Budget {
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self { shared, drained_until: Instant::now() }
    }

    pub(crate) fn request_handled(&self) {
        self.shared.request_handled();
    }

    /// Accounts for a response handed to the session.
    pub(crate) fn charge(&self, bytes: usize) {
        if bytes > 0 {
            self.shared.outstanding_bytes.fetch_add(bytes, Ordering::AcqRel);
        }
    }

    /// Whether another data response may be produced now.
    pub(crate) fn has_room(&mut self, now: Instant) -> bool {
        self.assume_drain(now);
        self.shared.outstanding_bytes.load(Ordering::Acquire) < RESPONSE_BUDGET_BYTES
    }

    /// A new connection answers nothing queued on the old one.
    pub(crate) fn reset(&mut self, now: Instant) {
        self.shared.outstanding_bytes.store(0, Ordering::Release);
        self.drained_until = now;
    }

    fn assume_drain(&mut self, now: Instant) {
        if self.shared.tracked.load(Ordering::Acquire) {
            self.drained_until = now;
            return;
        }
        let elapsed = now.saturating_duration_since(self.drained_until);
        let millis = usize::try_from(elapsed.as_millis()).unwrap_or(usize::MAX);
        let drained = millis.saturating_mul(UNTRACKED_DRAIN_BYTES_PER_SEC / 1000);
        if drained > 0 {
            saturating_sub(&self.shared.outstanding_bytes, drained);
            self.drained_until = now;
        }
    }

    /// How long the worker may sleep while requests wait for room.
    pub(crate) const POLL: Duration = Duration::from_millis(5);
}

#[cfg(test)]
mod tests {
    use ironrdp_cliprdr::pdu::{FileContentsResponse, FormatDataResponse};

    use super::*;

    #[test]
    fn requests_are_served_then_refused_then_dropped() {
        let shared = Shared::default();
        let verdicts: Vec<Admission> = (0..MAX_QUEUED_REQUESTS * 3).map(|_| shared.admit()).collect();
        assert!(verdicts[..MAX_QUEUED_REQUESTS].iter().all(|v| *v == Admission::Serve));
        assert!(verdicts[MAX_QUEUED_REQUESTS..MAX_QUEUED_REQUESTS * 2].iter().all(|v| *v == Admission::Refuse));
        assert!(verdicts[MAX_QUEUED_REQUESTS * 2..].iter().all(|v| *v == Admission::Drop));
        assert_eq!(shared.queued_requests(), MAX_QUEUED_REQUESTS * 2, "dropped requests are not counted");
        for _ in 0..MAX_QUEUED_REQUESTS * 2 {
            shared.request_handled();
        }
        assert_eq!(shared.admit(), Admission::Serve);
        shared.request_handled();
        shared.request_handled();
        assert_eq!(shared.queued_requests(), 0, "never underflows");
    }

    #[test]
    fn only_data_responses_cost_budget() {
        let data = ClipboardMessage::SendFormatData(FormatDataResponse::new_data(vec![0u8; 100]));
        assert_eq!(FlowControl::cost(&data), 100);
        let range = ClipboardMessage::SendFileContentsResponse(FileContentsResponse::new_data_response(1, vec![0; 7]));
        assert_eq!(FlowControl::cost(&range), 7);
        assert_eq!(FlowControl::cost(&ClipboardMessage::SendFormatData(FormatDataResponse::new_error())), 0);
        assert_eq!(FlowControl::cost(&ClipboardMessage::SendInitiateCopy(Vec::new())), 0);
    }

    #[test]
    fn tracked_budget_is_released_only_by_the_session() {
        let flow = FlowControl::default();
        let start = Instant::now();
        let mut budget = Budget::new(flow.shared());
        let message = ClipboardMessage::SendFormatData(FormatDataResponse::new_data(vec![0u8; 1024]));
        let guard = flow.track(&message);
        budget.charge(RESPONSE_BUDGET_BYTES);
        assert!(!budget.has_room(start));
        assert!(!budget.has_room(start + Duration::from_secs(3600)), "time does not free a tracked budget");
        flow.written(1024);
        assert!(budget.has_room(start), "below the budget again");
        budget.charge(1024);
        assert!(!budget.has_room(start));
        drop(guard);
        assert!(budget.has_room(start), "the guard released its message");
        flow.written(usize::MAX);
        assert!(budget.has_room(start), "over-release saturates");
    }

    #[test]
    fn untracked_budget_drains_at_the_assumed_rate() {
        let flow = FlowControl::default();
        let mut budget = Budget::new(flow.shared());
        let start = Instant::now();
        budget.reset(start);
        budget.charge(RESPONSE_BUDGET_BYTES + UNTRACKED_DRAIN_BYTES_PER_SEC);
        assert!(!budget.has_room(start));
        assert!(!budget.has_room(start + Duration::from_millis(900)));
        assert!(budget.has_room(start + Duration::from_millis(1100)));
        budget.charge(RESPONSE_BUDGET_BYTES);
        budget.reset(start + Duration::from_secs(2));
        assert!(budget.has_room(start + Duration::from_secs(2)), "a new connection starts empty");
    }
}
