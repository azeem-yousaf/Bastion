//! Backend-level tests: drive the real `CliprdrBackend` + worker with an in-memory OS
//! clipboard and a proxy that captures every `ClipboardMessage`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ironrdp_cliprdr::backend::{ClipboardMessage, ClipboardMessageProxy, CliprdrBackend, CliprdrBackendFactory as _};
use ironrdp_cliprdr::pdu::{
    ClipboardFileAttributes, ClipboardFormat, ClipboardFormatId, ClipboardFormatName, ClipboardGeneralCapabilityFlags,
    FileContentsFlags, FileContentsRequest, FileContentsResponse, FileDescriptor, FormatDataRequest,
    FormatDataResponse, LockDataId,
};
use ironrdp_cliprdr_native::data_control::find_mime_match;

use crate::backend::{BackendFactory, file_capabilities};
use crate::convert::{self, MIME_BASTION_REMOTE, MIME_PASSWORD_HINT};
use crate::flow::{FlowControl, MAX_QUEUED_REQUESTS, RESPONSE_BUDGET_BYTES};
use crate::os::{OfferItem, OsClipboard, Transfer};
use crate::uri;
use crate::worker::{Command, Config, HTML_FORMAT_ID, Worker};

// ---------------------------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct FakeState {
    /// Another client's selection.
    mimes: Vec<String>,
    data: HashMap<String, Vec<u8>>,
    /// Our own offer, when we own the selection.
    owner: bool,
    offered: Vec<OfferItem>,
    generation: u64,
    reads: Vec<String>,
}

#[derive(Clone, Default)]
struct FakeOs(Arc<Mutex<FakeState>>);

impl FakeOs {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().expect("fake os lock")
    }
}

impl OsClipboard for FakeOs {
    fn is_owner(&self) -> bool {
        self.state().owner
    }

    fn mime_types(&self) -> Vec<String> {
        let s = self.state();
        if s.owner { s.offered.iter().map(|o| o.mime.clone()).collect() } else { s.mimes.clone() }
    }

    fn read(&mut self, mime: &str) -> Result<Option<Vec<u8>>, String> {
        let mut s = self.state();
        s.reads.push(mime.to_owned());
        if s.owner {
            return Ok(None);
        }
        Ok(find_mime_match(mime, &s.mimes).and_then(|m| s.data.get(m).cloned()))
    }

    fn offer(&mut self, items: &[OfferItem], generation: u64) -> Result<(), String> {
        let mut s = self.state();
        s.owner = true;
        s.offered = items.to_vec();
        s.generation = generation;
        Ok(())
    }

    fn clear(&mut self) {
        let mut s = self.state();
        s.owner = false;
        s.offered.clear();
    }
}

#[derive(Debug, Clone, Default)]
struct Capture(Arc<Mutex<Vec<ClipboardMessage>>>);

impl ClipboardMessageProxy for Capture {
    fn send_clipboard_message(&self, message: ClipboardMessage) {
        self.0.lock().expect("capture lock").push(message);
    }
}

struct Harness {
    worker: Worker<FakeOs, Capture>,
    tx: Sender<Command>,
    rx: Receiver<Command>,
    backend: Box<dyn CliprdrBackend>,
    os: FakeOs,
    capture: Capture,
    base: tempfile::TempDir,
    flow: FlowControl,
}

impl Harness {
    fn new(files: bool, max: usize) -> Self {
        let base = tempfile::tempdir().expect("tmp");
        let (tx, rx) = mpsc::channel();
        let os = FakeOs::default();
        let capture = Capture::default();
        let mut config = Config::new(files, max);
        config.download_base = Some(base.path().to_owned());
        config.paste_timeout = Duration::from_secs(5);
        let flow = config.flow.clone();
        let worker = Worker::new(os.clone(), capture.clone(), config);
        let factory = BackendFactory { commands: tx.clone(), files, max_transfer_bytes: max, flow: flow.shared() };
        let backend = factory.build_cliprdr_backend();
        let mut h = Self { worker, tx, rx, backend, os, capture, base, flow };
        h.pump();
        h
    }

    fn pump(&mut self) {
        while let Ok(c) = self.rx.try_recv() {
            self.worker.handle(c);
        }
    }

    fn take(&self) -> Vec<ClipboardMessage> {
        core::mem::take(&mut *self.capture.0.lock().expect("lock"))
    }

    /// Channel setup as `Cliprdr` drives it: capabilities, Monitor Ready, Format List Response.
    fn connect(&mut self) -> Vec<ClipboardMessage> {
        let caps = ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES | file_capabilities();
        self.backend.on_process_negotiated_capabilities(caps);
        self.backend.on_request_format_list();
        self.pump();
        let initial = self.take();
        self.backend.on_ready();
        self.pump();
        let mut all = initial;
        all.extend(self.take());
        all
    }

    /// Another application copies `items` locally.
    fn local_copy(&mut self, items: &[(&str, &[u8])]) {
        {
            let mut s = self.os.state();
            s.owner = false;
            s.offered.clear();
            s.mimes = items.iter().map(|(m, _)| (*m).to_owned()).collect();
            s.data = items.iter().map(|(m, d)| ((*m).to_owned(), d.to_vec())).collect();
        }
        self.tx.send(Command::LocalChanged).expect("send");
        self.pump();
    }

    /// A local application pastes `mime` from our offer.
    fn paste(&mut self, mime: &str) -> Receiver<Option<Vec<u8>>> {
        let generation = self.os.state().generation;
        let (tx, rx) = mpsc::channel();
        let transfer = Transfer::new(mime.to_owned(), generation, move |d| {
            let _ = tx.send(d);
        });
        self.tx.send(Command::Paste(transfer)).expect("send");
        self.pump();
        rx
    }

    /// The content types of our local offer (without the marker every offer carries).
    fn offered_mimes(&self) -> Vec<String> {
        self.os.state().offered.iter().map(|o| o.mime.clone()).filter(|m| m != MIME_BASTION_REMOTE).collect()
    }

    fn remote_copy(&mut self, formats: &[ClipboardFormat]) {
        self.backend.on_remote_copy(formats);
        self.pump();
    }
}

fn initiate_copy(msgs: &[ClipboardMessage]) -> Vec<ClipboardFormatId> {
    msgs.iter()
        .find_map(|m| match m {
            ClipboardMessage::SendInitiateCopy(f) => Some(f.iter().map(|f| f.id()).collect()),
            _ => None,
        })
        .expect("SendInitiateCopy")
}

fn format_data(msgs: Vec<ClipboardMessage>) -> Option<Vec<u8>> {
    let [ClipboardMessage::SendFormatData(r)] = <[_; 1]>::try_from(msgs).expect("one message") else {
        panic!("expected SendFormatData")
    };
    (!r.is_error()).then(|| r.data().to_vec())
}

fn paste_request(msgs: &[ClipboardMessage]) -> ClipboardFormatId {
    match msgs {
        [ClipboardMessage::SendInitiatePaste(id)] => *id,
        other => panic!("expected one SendInitiatePaste, got {other:?}"),
    }
}

fn delivered(rx: &Receiver<Option<Vec<u8>>>) -> Option<Vec<u8>> {
    rx.try_recv().expect("paste answered")
}

const CF_HTML_REMOTE: ClipboardFormatId = ClipboardFormatId(0xC09E);
const FILE_LIST_REMOTE: ClipboardFormatId = ClipboardFormatId(0xC0F1);

fn sample_png() -> Vec<u8> {
    let img = image::RgbaImage::from_fn(3, 2, |x, y| image::Rgba([x as u8 * 80, y as u8 * 100, 7, 255]));
    let mut png = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png).expect("png");
    png
}

// ---------------------------------------------------------------------------------------------
// Local -> remote
// ---------------------------------------------------------------------------------------------

#[test]
fn capabilities_follow_files_option() {
    let h = Harness::new(true, 1 << 20);
    let caps = h.backend.client_capabilities();
    assert!(caps.contains(ClipboardGeneralCapabilityFlags::STREAM_FILECLIP_ENABLED));
    assert!(caps.contains(ClipboardGeneralCapabilityFlags::FILECLIP_NO_FILE_PATHS));
    assert!(caps.contains(ClipboardGeneralCapabilityFlags::CAN_LOCK_CLIPDATA));
    assert!(caps.contains(ClipboardGeneralCapabilityFlags::HUGE_FILE_SUPPORT_ENABLED));
    let h = Harness::new(false, 1 << 20);
    assert!(h.backend.client_capabilities().is_empty());
}

#[test]
fn initial_format_list_reflects_local_clipboard() {
    let mut h = Harness::new(true, 1 << 20);
    h.os.state().mimes = vec!["text/plain;charset=utf-8".to_owned()];
    let msgs = h.connect();
    assert_eq!(initiate_copy(&msgs), vec![ClipboardFormatId::CF_UNICODETEXT]);
    assert_eq!(msgs.len(), 1);
}

#[test]
fn local_text_copy_advertises_and_renders_unicode_text() {
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    h.local_copy(&[("text/plain;charset=utf-8", "h\u{e9}llo\nworld \u{1F600}".as_bytes()), ("text/plain", b"x")]);
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);

    h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
    h.pump();
    let data = format_data(h.take()).expect("data");
    assert_eq!(data, convert::text_to_cf_unicodetext("h\u{e9}llo\r\nworld \u{1F600}"));
}

#[test]
fn local_string_only_text_is_latin1() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.local_copy(&[("STRING", b"caf\xe9")]);
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);
    h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
    h.pump();
    assert_eq!(format_data(h.take()).expect("data"), convert::text_to_cf_unicodetext("caf\u{e9}"));
}

#[test]
fn local_html_and_image_copy() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    let png = sample_png();
    h.local_copy(&[("text/html", b"<b>bold</b>"), ("text/plain", b"bold"), ("image/png", &png)]);
    let msgs = h.take();
    let ClipboardMessage::SendInitiateCopy(formats) = &msgs[0] else { panic!("expected copy") };
    let html = formats.iter().find(|f| f.id() == HTML_FORMAT_ID).expect("html format");
    assert_eq!(html.name.as_ref().map(ClipboardFormatName::value), Some("HTML Format"));
    let ids: Vec<_> = formats.iter().map(|f| f.id()).collect();
    assert!(ids.contains(&ClipboardFormatId::CF_UNICODETEXT));
    assert!(ids.contains(&ClipboardFormatId::CF_DIB));
    assert!(ids.contains(&ClipboardFormatId::CF_DIBV5));

    h.backend.on_format_data_request(FormatDataRequest { format: HTML_FORMAT_ID });
    h.pump();
    let cf_html = format_data(h.take()).expect("html");
    let back = convert::cf_html_to_local_html(&cf_html).expect("valid CF_HTML");
    assert!(String::from_utf8(back).expect("utf8").ends_with("<b>bold</b>"));

    for (format, decode) in [
        (ClipboardFormatId::CF_DIB, convert::dib_to_png as fn(&[u8]) -> _),
        (ClipboardFormatId::CF_DIBV5, convert::dibv5_to_png),
    ] {
        h.backend.on_format_data_request(FormatDataRequest { format });
        h.pump();
        let dib = format_data(h.take()).expect("dib");
        let back = decode(&dib).expect("decodes");
        let a = image::load_from_memory(&back).expect("png").to_rgba8();
        let b = image::load_from_memory(&png).expect("png").to_rgba8();
        assert_eq!(a.dimensions(), b.dimensions());
        assert_eq!(a.get_pixel(2, 1).0[..3], b.get_pixel(2, 1).0[..3]);
    }
}

#[test]
fn local_data_over_limit_is_refused() {
    let mut h = Harness::new(false, 64);
    h.connect();
    let big = "x".repeat(100);
    h.local_copy(&[("text/plain;charset=utf-8", big.as_bytes())]);
    h.take();
    h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
    h.pump();
    assert_eq!(format_data(h.take()), None);
}

#[test]
fn unsupported_or_vanished_format_answers_with_error() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.local_copy(&[("text/plain", b"x")]);
    h.take();
    h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_DIB });
    h.pump();
    assert_eq!(format_data(h.take()), None);
    h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId(0xC123) });
    h.pump();
    assert_eq!(format_data(h.take()), None);
}

#[test]
fn local_change_before_ready_is_deferred() {
    let mut h = Harness::new(false, 1 << 20);
    h.local_copy(&[("text/plain", b"early")]);
    assert!(h.take().is_empty(), "nothing is sent before the channel exists");
    let caps = ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES;
    h.backend.on_process_negotiated_capabilities(caps);
    h.backend.on_request_format_list();
    h.pump();
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);
    h.local_copy(&[("image/png", &sample_png())]);
    assert!(h.take().is_empty(), "initialization FormatList is still unanswered");
    h.backend.on_ready();
    h.pump();
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_DIBV5, ClipboardFormatId::CF_DIB]);
}

// ---------------------------------------------------------------------------------------------
// Remote -> local
// ---------------------------------------------------------------------------------------------

#[test]
fn remote_text_copy_is_offered_and_pasted() {
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    h.remote_copy(&[
        ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
        ClipboardFormat::new(ClipboardFormatId::CF_TEXT),
    ]);
    assert_eq!(h.offered_mimes(), vec!["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"]);
    assert!(h.take().is_empty(), "delayed rendering: nothing requested yet");

    let rx = h.paste("text/plain;charset=utf-8");
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_UNICODETEXT);
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
    // A second paste while the first is in flight waits for the same response.
    let rx2 = h.paste("UTF8_STRING");
    assert!(h.take().is_empty());

    let wire = convert::text_to_cf_unicodetext("line1\nline2 \u{4e16}");
    h.backend.on_format_data_response(FormatDataResponse::new_data(wire.as_slice()));
    h.pump();
    assert_eq!(delivered(&rx).expect("data"), "line1\nline2 \u{4e16}".as_bytes());
    assert_eq!(delivered(&rx2).expect("data"), "line1\nline2 \u{4e16}".as_bytes());

    // Cached for later pastes of the same copy.
    let rx3 = h.paste("text/plain");
    assert!(h.take().is_empty());
    assert_eq!(delivered(&rx3).expect("cached"), "line1\nline2 \u{4e16}".as_bytes());
}

#[test]
fn remote_html_and_image() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.remote_copy(&[
        ClipboardFormat::new(CF_HTML_REMOTE).with_name(ClipboardFormatName::HTML),
        ClipboardFormat::new(ClipboardFormatId::CF_DIB),
        ClipboardFormat::new(ClipboardFormatId::CF_DIBV5),
    ]);
    assert_eq!(h.offered_mimes(), vec!["text/html", "image/png"]);

    let rx = h.paste("text/html");
    assert_eq!(paste_request(&h.take()), CF_HTML_REMOTE);
    let cf = convert::local_html_to_cf_html(b"<i>remote</i>");
    h.backend.on_format_data_response(FormatDataResponse::new_data(cf.as_slice()));
    h.pump();
    let html = String::from_utf8(delivered(&rx).expect("html")).expect("utf8");
    assert!(html.ends_with("<i>remote</i>"));

    let rx = h.paste("image/png");
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_DIBV5, "DIBV5 preferred (keeps alpha)");
    let dib = convert::png_to_dibv5(&sample_png()).expect("dib");
    h.backend.on_format_data_response(FormatDataResponse::new_data(dib.as_slice()));
    h.pump();
    let png = delivered(&rx).expect("png");
    assert_eq!(image::load_from_memory(&png).expect("png").to_rgba8().dimensions(), (3, 2));
}

#[test]
fn corrupt_remote_data_fails_the_paste_only() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_DIB)]);
    let rx = h.paste("image/png");
    h.take();
    h.backend.on_format_data_response(FormatDataResponse::new_data(&[1u8, 2, 3][..]));
    h.pump();
    assert_eq!(delivered(&rx), None);
    // Remote failure response.
    let rx = h.paste("image/png");
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_DIB);
    h.backend.on_format_data_response(FormatDataResponse::new_error());
    h.pump();
    assert_eq!(delivered(&rx), None);
}

#[test]
fn oversized_remote_response_is_dropped() {
    let mut h = Harness::new(false, 16);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    let rx = h.paste("text/plain");
    h.take();
    let wire = convert::text_to_cf_unicodetext("this is longer than sixteen bytes");
    h.backend.on_format_data_response(FormatDataResponse::new_data(wire.as_slice()));
    h.pump();
    assert_eq!(delivered(&rx), None);
}

#[test]
fn unanswered_paste_times_out_without_wedging_later_pastes() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.remote_copy(&[
        ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
        ClipboardFormat::new(ClipboardFormatId::CF_DIB),
    ]);
    let rx_text = h.paste("text/plain");
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_UNICODETEXT);
    h.worker.tick(Instant::now() + Duration::from_secs(6));
    assert_eq!(delivered(&rx_text), None, "the local paste is failed after the timeout");

    // A new paste is still sent although the first request was never answered.
    let rx_png = h.paste("image/png");
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_DIB);
    // Late answer to the text request arrives first and must not be taken as the image.
    let wire = convert::text_to_cf_unicodetext("late");
    h.backend.on_format_data_response(FormatDataResponse::new_data(wire.as_slice()));
    h.pump();
    assert_eq!(rx_png.try_recv(), Err(TryRecvError::Empty));
    let dib = convert::png_to_dib(&sample_png()).expect("dib");
    h.backend.on_format_data_response(FormatDataResponse::new_data(dib.as_slice()));
    h.pump();
    assert!(delivered(&rx_png).is_some());
    // And the late text was cached for the next text paste.
    let rx = h.paste("text/plain");
    assert!(h.take().is_empty());
    assert_eq!(delivered(&rx).expect("cached"), b"late");
}

#[test]
fn stale_paste_after_new_remote_copy_fails() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    let rx = h.paste("text/plain");
    h.take();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    assert_eq!(delivered(&rx), None, "waiters of the old copy are failed");
    let wire = convert::text_to_cf_unicodetext("old");
    h.backend.on_format_data_response(FormatDataResponse::new_data(wire.as_slice()));
    h.pump();
    let rx = h.paste("text/plain");
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_UNICODETEXT, "old data is not reused");
    drop(rx);
}

#[test]
fn unsupported_remote_copy_keeps_local_clipboard() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_ENHMETAFILE)]);
    assert!(!h.os.state().owner);
    // Unless we already own it with an older remote copy: then the old offer is withdrawn.
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    assert!(h.os.state().owner);
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_ENHMETAFILE)]);
    assert!(h.offered_mimes().is_empty());
}

#[test]
fn clipboard_manager_echo_is_not_re_announced() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.take();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    let rx = h.paste("text/plain;charset=utf-8");
    h.take();
    let wire = convert::text_to_cf_unicodetext("from remote");
    h.backend.on_format_data_response(FormatDataResponse::new_data(wire.as_slice()));
    h.pump();
    assert!(delivered(&rx).is_some());
    // Klipper takes over the selection with the same content.
    h.local_copy(&[("text/plain;charset=utf-8", b"from remote")]);
    assert!(h.take().is_empty(), "echo must not be sent back to the remote");
    // A genuinely new local copy is announced.
    h.local_copy(&[("text/plain;charset=utf-8", b"typed locally")]);
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);
}

#[test]
fn reconnect_resets_state() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    let rx = h.paste("text/plain");
    h.take();
    // Engine reconnects: a new backend is built.
    let factory =
        BackendFactory { commands: h.tx.clone(), files: false, max_transfer_bytes: 1 << 20, flow: h.flow.shared() };
    h.backend = factory.build_cliprdr_backend();
    h.pump();
    assert_eq!(delivered(&rx), None);
    assert!(!h.os.state().owner, "remote offer withdrawn on reconnect");
    // The old channel's answer never arrives; the new channel works normally.
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    let rx = h.paste("text/plain");
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_UNICODETEXT);
    let wire = convert::text_to_cf_unicodetext("new");
    h.backend.on_format_data_response(FormatDataResponse::new_data(wire.as_slice()));
    h.pump();
    assert_eq!(delivered(&rx).expect("data"), b"new");
}

// ---------------------------------------------------------------------------------------------
// Files: local -> remote
// ---------------------------------------------------------------------------------------------

fn file_contents(h: &mut Harness, req: FileContentsRequest) -> FileContentsResponse<'static> {
    h.backend.on_file_contents_request(req);
    h.pump();
    let msgs = h.take();
    let [ClipboardMessage::SendFileContentsResponse(r)] = <[_; 1]>::try_from(msgs).expect("one") else {
        panic!("expected SendFileContentsResponse")
    };
    r
}

fn range(stream_id: u32, index: i32, position: u64, size: u32, data_id: Option<u32>) -> FileContentsRequest {
    FileContentsRequest { stream_id, index, flags: FileContentsFlags::RANGE, position, requested_size: size, data_id }
}

#[test]
fn local_file_copy_is_offered_and_served() {
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    let src = tempfile::tempdir().expect("tmp");
    let dir = src.path().join("My Folder");
    std::fs::create_dir(&dir).expect("mkdir");
    let content: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
    std::fs::write(dir.join("data.bin"), &content).expect("write");
    let single = src.path().join("r\u{e9}sum\u{e9}.txt");
    std::fs::write(&single, b"cv").expect("write");
    let uris = uri::build_uri_list(&[dir.clone(), single]);
    h.local_copy(&[("text/uri-list", &uris), ("text/plain", b"paths")]);

    let msgs = h.take();
    let [ClipboardMessage::SendInitiateFileCopy(files)] = msgs.as_slice() else {
        panic!("expected file copy: {msgs:?}")
    };
    let names: Vec<_> = files.iter().map(|f| (f.relative_path.clone(), f.name.clone(), f.file_size)).collect();
    assert_eq!(
        names,
        vec![
            (None, "My Folder".to_owned(), Some(0)),
            (Some("My Folder".to_owned()), "data.bin".to_owned(), Some(5000)),
            (None, "r\u{e9}sum\u{e9}.txt".to_owned(), Some(2)),
        ]
    );

    let size = file_contents(
        &mut h,
        FileContentsRequest {
            stream_id: 1,
            index: 1,
            flags: FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: None,
        },
    );
    assert_eq!(size.data_as_size().expect("size"), 5000);
    let r = file_contents(&mut h, range(2, 1, 4096, 4096, None));
    assert_eq!((r.stream_id(), r.data()), (2, &content[4096..]));
    let r = file_contents(&mut h, range(3, 2, 0, 100, None));
    assert_eq!(r.data(), b"cv");
    assert!(file_contents(&mut h, range(4, 9, 0, 1, None)).is_error(), "bad index");
    assert!(file_contents(&mut h, range(5, -1, 0, 1, None)).is_error(), "negative index");

    // Server locks the clipboard, then the local clipboard changes to text: the locked snapshot
    // still serves requests that carry the lock id, the unlocked list does not.
    h.backend.on_lock(LockDataId(77));
    h.pump();
    h.local_copy(&[("text/plain", b"new")]);
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);
    assert_eq!(file_contents(&mut h, range(6, 2, 0, 100, Some(77))).data(), b"cv");
    assert!(file_contents(&mut h, range(7, 2, 0, 100, None)).is_error());
    h.backend.on_unlock(LockDataId(77));
    h.pump();
    assert!(file_contents(&mut h, range(8, 2, 0, 100, Some(77))).is_error());
}

#[test]
fn local_files_over_limit_fall_back_to_text() {
    let mut h = Harness::new(true, 100);
    h.connect();
    let src = tempfile::tempdir().expect("tmp");
    let f = src.path().join("big");
    std::fs::write(&f, vec![0u8; 1000]).expect("write");
    h.local_copy(&[("text/uri-list", &uri::build_uri_list(&[f])), ("text/plain", b"big")]);
    let msgs = h.take();
    assert!(msgs.iter().any(|m| matches!(m, ClipboardMessage::Error(_))), "user is told why");
    assert_eq!(initiate_copy(&msgs), vec![ClipboardFormatId::CF_UNICODETEXT]);
}

#[test]
fn files_disabled_offers_no_file_list() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    let src = tempfile::tempdir().expect("tmp");
    let f = src.path().join("a");
    std::fs::write(&f, b"a").expect("write");
    h.local_copy(&[("text/uri-list", &uri::build_uri_list(&[f])), ("text/plain", b"a")]);
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);
    h.remote_copy(&[ClipboardFormat::new(FILE_LIST_REMOTE).with_name(ClipboardFormatName::FILE_LIST)]);
    assert!(!h.os.state().owner, "remote file lists are not offered when files are disabled");
}

#[test]
fn non_file_uri_list_is_not_a_file_copy() {
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    h.local_copy(&[("text/uri-list", b"https://example.com/\r\n"), ("text/plain", b"https://example.com/")]);
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);
}

// ---------------------------------------------------------------------------------------------
// Files: remote -> local
// ---------------------------------------------------------------------------------------------

fn remote_files() -> (Vec<FileDescriptor>, Vec<Vec<u8>>) {
    let big: Vec<u8> = (0..(crate::files::download::CHUNK_BYTES as usize + 10)).map(|i| (i % 253) as u8).collect();
    let files = vec![
        FileDescriptor::new("Report").with_attributes(ClipboardFileAttributes::DIRECTORY),
        FileDescriptor::new("big.bin")
            .with_attributes(ClipboardFileAttributes::ARCHIVE)
            .with_file_size(big.len() as u64)
            .with_relative_path("Report"),
        FileDescriptor::new("notes \u{1F4DD}.txt").with_attributes(ClipboardFileAttributes::ARCHIVE).with_file_size(5),
    ];
    (files, vec![Vec::new(), big, b"notes".to_vec()])
}

/// Plays the server: answers every FileContentsRequest the worker sends until it stops.
fn serve_download(h: &mut Harness, contents: &[Vec<u8>], lock: Option<u32>) -> usize {
    let mut served = 0;
    loop {
        let msgs = h.take();
        let mut any = false;
        for m in msgs {
            let ClipboardMessage::SendFileContentsRequest(req) = m else { continue };
            any = true;
            served += 1;
            assert_eq!(req.data_id, lock);
            let data = &contents[usize::try_from(req.index).expect("index")];
            let resp = if req.flags.contains(FileContentsFlags::SIZE) {
                FileContentsResponse::new_size_response(req.stream_id, data.len() as u64)
            } else {
                let start = usize::try_from(req.position).expect("pos");
                let end = (start + req.requested_size as usize).min(data.len());
                FileContentsResponse::new_data_response(req.stream_id, data[start..end].to_vec())
            };
            h.backend.on_file_contents_response(resp);
            h.pump();
        }
        if !any {
            return served;
        }
    }
}

#[test]
fn remote_file_copy_downloads_on_paste() {
    let mut h = Harness::new(true, 4 << 20);
    h.connect();
    h.remote_copy(&[
        ClipboardFormat::new(FILE_LIST_REMOTE).with_name(ClipboardFormatName::FILE_LIST),
        ClipboardFormat::new(ClipboardFormatId(0xC0F2)).with_name(ClipboardFormatName::PREFERRED_DROP_EFFECT),
    ]);
    assert_eq!(h.offered_mimes(), vec!["text/uri-list", "x-special/gnome-copied-files"]);
    assert!(h.take().is_empty());

    let rx = h.paste("text/uri-list");
    assert_eq!(paste_request(&h.take()), FILE_LIST_REMOTE);
    let rx_gnome = h.paste("x-special/gnome-copied-files");
    assert!(h.take().is_empty(), "joins the running download");

    let (files, contents) = remote_files();
    h.backend.on_remote_file_list(&files, Some(5));
    h.pump();
    let requests = serve_download(&mut h, &contents, Some(5));
    assert_eq!(requests, 3, "two chunks of big.bin + one for notes");

    let list = delivered(&rx).expect("uri list");
    let paths = uri::parse_uri_list(&list);
    assert_eq!(paths.len(), 2);
    assert!(paths.iter().all(|p| p.starts_with(h.base.path())));
    assert_eq!(paths[0].file_name().and_then(|n| n.to_str()), Some("Report"));
    assert_eq!(std::fs::read(paths[0].join("big.bin")).expect("read"), contents[1]);
    assert_eq!(std::fs::read(&paths[1]).expect("read"), b"notes");
    let gnome = String::from_utf8(delivered(&rx_gnome).expect("gnome")).expect("utf8");
    assert!(gnome.starts_with("copy\nfile://"));
    assert_eq!(uri::parse_gnome_copied_files(gnome.as_bytes()), paths);

    // Later pastes reuse the download.
    let rx = h.paste("text/uri-list");
    assert!(h.take().is_empty());
    assert_eq!(delivered(&rx).expect("cached"), list);

    // Our own downloaded files coming back through a clipboard manager are not re-uploaded.
    h.local_copy(&[("text/uri-list", &list)]);
    assert!(h.take().iter().all(|m| !matches!(m, ClipboardMessage::SendInitiateFileCopy(_))));

    // A new remote copy keeps the previous download for a while (pastes may still be reading it).
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    assert!(paths[1].exists());
}

#[test]
fn remote_file_download_respects_limits() {
    let mut h = Harness::new(true, 1000);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(FILE_LIST_REMOTE).with_name(ClipboardFormatName::FILE_LIST)]);
    let rx = h.paste("text/uri-list");
    h.take();
    let (files, _) = remote_files();
    h.backend.on_remote_file_list(&files, None);
    h.pump();
    assert_eq!(delivered(&rx), None);
    let msgs = h.take();
    assert!(matches!(msgs.as_slice(), [ClipboardMessage::Error(_)]), "only an error, no requests: {msgs:?}");
    assert_eq!(std::fs::read_dir(h.base.path()).expect("ls").count(), 0, "nothing written");
    // Retrying the same copy fails immediately without asking the server again.
    let rx = h.paste("text/uri-list");
    assert!(h.take().is_empty());
    assert_eq!(delivered(&rx), None);
}

#[test]
fn remote_lying_about_size_is_cut_off() {
    let mut h = Harness::new(true, 100);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(FILE_LIST_REMOTE).with_name(ClipboardFormatName::FILE_LIST)]);
    let rx = h.paste("text/uri-list");
    h.take();
    // No size in the descriptor: the SIZE answer is what gets checked.
    let files = vec![FileDescriptor::new("f").with_attributes(ClipboardFileAttributes::ARCHIVE)];
    h.backend.on_remote_file_list(&files, None);
    h.pump();
    let msgs = h.take();
    let [ClipboardMessage::SendFileContentsRequest(req)] = msgs.as_slice() else { panic!("expected size request") };
    assert!(req.flags.contains(FileContentsFlags::SIZE));
    h.backend.on_file_contents_response(FileContentsResponse::new_size_response(req.stream_id, 1 << 40));
    h.pump();
    assert_eq!(delivered(&rx), None);
    assert!(h.take().iter().any(|m| matches!(m, ClipboardMessage::Error(_))));
}

#[test]
fn remote_file_failure_and_stall_release_pastes() {
    let mut h = Harness::new(true, 4 << 20);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(FILE_LIST_REMOTE).with_name(ClipboardFormatName::FILE_LIST)]);
    let rx = h.paste("text/uri-list");
    h.take();
    let (files, _) = remote_files();
    h.backend.on_remote_file_list(&files, None);
    h.pump();
    let msgs = h.take();
    let [ClipboardMessage::SendFileContentsRequest(req)] = msgs.as_slice() else { panic!("expected request") };
    h.backend.on_file_contents_response(FileContentsResponse::new_error(req.stream_id));
    h.pump();
    assert_eq!(delivered(&rx), None);
    assert!(matches!(h.take().as_slice(), [ClipboardMessage::Error(_)]));
    let dirs: Vec<PathBuf> = std::fs::read_dir(h.base.path()).expect("ls").map(|e| e.expect("e").path()).collect();
    assert!(dirs.is_empty(), "partial download removed: {dirs:?}");

    // Retry is allowed after a transient failure; a server that then goes silent is timed out.
    let rx = h.paste("text/uri-list");
    assert_eq!(paste_request(&h.take()), FILE_LIST_REMOTE);
    h.worker.tick(Instant::now() + Duration::from_secs(120));
    assert_eq!(delivered(&rx), None);
    assert!(h.take().iter().any(|m| matches!(m, ClipboardMessage::Error(_))));
}

#[test]
fn remote_file_list_refused_by_server() {
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    h.remote_copy(&[
        ClipboardFormat::new(FILE_LIST_REMOTE).with_name(ClipboardFormatName::FILE_LIST),
        ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
    ]);
    let rx = h.paste("text/uri-list");
    h.take();
    // Cliprdr routes a failed file-list response to on_format_data_response.
    h.backend.on_format_data_response(FormatDataResponse::new_error());
    h.pump();
    assert_eq!(delivered(&rx), None);
    // Request order stays in sync: the next text paste gets its own answer.
    let rx = h.paste("text/plain");
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_UNICODETEXT);
    let wire = convert::text_to_cf_unicodetext("ok");
    h.backend.on_format_data_response(FormatDataResponse::new_data(wire.as_slice()));
    h.pump();
    assert_eq!(delivered(&rx).expect("text"), b"ok");
}

#[test]
fn every_waiting_paste_gets_the_remote_data() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    let waiting: Vec<_> = (0..3).map(|_| h.paste("text/plain;charset=utf-8")).collect();
    assert_eq!(paste_request(&h.take()), ClipboardFormatId::CF_UNICODETEXT, "one request serves all three");
    let wire = convert::text_to_cf_unicodetext("shared");
    h.backend.on_format_data_response(FormatDataResponse::new_data(wire.as_slice()));
    h.pump();
    for rx in &waiting {
        assert_eq!(delivered(rx).expect("data"), b"shared");
    }
    // And the cache still answers later pastes.
    let rx = h.paste("text/plain");
    assert!(h.take().is_empty());
    assert_eq!(delivered(&rx).expect("cached"), b"shared");
}

// ---------------------------------------------------------------------------------------------
// Hostile servers: request floods
// ---------------------------------------------------------------------------------------------

fn is_error_response(message: &ClipboardMessage) -> bool {
    match message {
        ClipboardMessage::SendFormatData(r) => r.is_error(),
        ClipboardMessage::SendFileContentsResponse(r) => r.is_error(),
        other => panic!("unexpected message {other:?}"),
    }
}

#[test]
fn file_contents_flood_is_bounded_in_requests_and_bytes() {
    const CHUNK: u32 = 8 * 1024 * 1024;
    let mut h = Harness::new(true, 64 << 20);
    h.connect();
    // The session reports what it wrote (as the engine does).
    h.flow.written(0);
    let src = tempfile::tempdir().expect("tmp");
    let f = src.path().join("big.bin");
    std::fs::File::create(&f).expect("create").set_len(u64::from(CHUNK)).expect("sparse 8 MiB file");
    h.local_copy(&[("text/uri-list", &uri::build_uri_list(&[f]))]);
    assert!(matches!(h.take().as_slice(), [ClipboardMessage::SendInitiateFileCopy(_)]));

    // The server sends 1,000 requests for 8 MiB each (8 GB of answers) before the worker runs.
    for stream in 0..1000 {
        h.backend.on_file_contents_request(range(stream, 0, 0, CHUNK, None));
    }
    assert_eq!(h.flow.shared().queued_requests(), MAX_QUEUED_REQUESTS * 2, "the request queue is capped");
    let mut queued = 0;
    while let Ok(command) = h.rx.try_recv() {
        queued += 1;
        h.worker.handle(command);
    }
    assert_eq!(queued, MAX_QUEUED_REQUESTS * 2);
    assert_eq!(h.flow.shared().queued_requests(), 0);

    // Nothing has been written yet: only as much data as the budget allows was produced, the
    // rest was refused (or waits).
    let first = h.take();
    let data_bytes: usize = first.iter().map(FlowControl::cost).sum();
    assert!(data_bytes >= CHUNK as usize, "some requests are served");
    assert!(data_bytes < RESPONSE_BUDGET_BYTES + CHUNK as usize, "queued {data_bytes} bytes");
    let served = first.iter().filter(|m| !is_error_response(m)).count();
    let refused = first.len() - served;
    assert!(refused >= MAX_QUEUED_REQUESTS, "excess requests get a failure response ({refused})");

    // Time alone frees nothing while the session is still writing.
    h.worker.tick(Instant::now() + Duration::from_secs(60));
    assert!(h.take().is_empty());

    // As the session writes responses out, the held-back requests are served, never more than
    // the budget at a time.
    let mut pending = first;
    let mut later = 0;
    for _ in 0..100 {
        for message in pending.drain(..) {
            drop(h.flow.track(&message));
        }
        h.worker.tick(Instant::now());
        pending = h.take();
        if pending.is_empty() {
            break;
        }
        let bytes: usize = pending.iter().map(FlowControl::cost).sum();
        assert!(bytes < RESPONSE_BUDGET_BYTES + CHUNK as usize);
        assert!(pending.iter().all(|m| !is_error_response(m)));
        later += pending.len();
    }
    assert!(later > 0, "held-back requests are answered once there is room");
    assert_eq!(served + later + refused, MAX_QUEUED_REQUESTS * 2, "every queued request is answered exactly once");

    // The clipboard still works afterwards.
    let r = file_contents(&mut h, range(5000, 0, 0, 16, None));
    assert_eq!(r.data(), &[0u8; 16]);
}

#[test]
fn size_requests_are_answered_even_when_the_budget_is_used_up() {
    const CHUNK: u32 = 8 * 1024 * 1024;
    let mut h = Harness::new(true, 64 << 20);
    h.connect();
    h.flow.written(0);
    let src = tempfile::tempdir().expect("tmp");
    let f = src.path().join("big.bin");
    std::fs::File::create(&f).expect("create").set_len(u64::from(CHUNK)).expect("sparse file");
    h.local_copy(&[("text/uri-list", &uri::build_uri_list(&[f]))]);
    h.take();
    for stream in 0..8 {
        h.backend.on_file_contents_request(range(stream, 0, 0, CHUNK, None));
    }
    h.pump();
    let served = h.take();
    assert!(served.len() < 8, "the budget holds some requests back");
    let size = file_contents(
        &mut h,
        FileContentsRequest {
            stream_id: 99,
            index: 0,
            flags: FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: None,
        },
    );
    assert_eq!(size.data_as_size().expect("size"), u64::from(CHUNK));
    // A reconnect forgets what was queued for the old connection.
    let factory =
        BackendFactory { commands: h.tx.clone(), files: true, max_transfer_bytes: 64 << 20, flow: h.flow.shared() };
    h.backend = factory.build_cliprdr_backend();
    h.pump();
    h.worker.tick(Instant::now());
    assert!(h.take().is_empty(), "held-back requests of the old connection are dropped");
}

#[test]
fn format_data_request_flood_is_refused_beyond_the_queue() {
    let mut h = Harness::new(false, 1 << 20);
    h.connect();
    h.local_copy(&[("text/plain;charset=utf-8", b"hello")]);
    h.take();
    for _ in 0..10_000 {
        h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
    }
    h.pump();
    let msgs = h.take();
    assert_eq!(msgs.len(), MAX_QUEUED_REQUESTS * 2, "requests beyond the queue are not even queued");
    assert_eq!(msgs.iter().filter(|m| is_error_response(m)).count(), MAX_QUEUED_REQUESTS);
    // Once the queue has drained, requests are served again.
    h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
    h.pump();
    assert_eq!(format_data(h.take()).expect("data"), convert::text_to_cf_unicodetext("hello"));
}

// ---------------------------------------------------------------------------------------------
// Selections that must not reach the remote
// ---------------------------------------------------------------------------------------------

#[test]
fn password_manager_secrets_are_never_announced_or_served() {
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    h.local_copy(&[("text/plain;charset=utf-8", b"an ordinary copy")]);
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);

    // KeePassXC copies a password: the hint rides along with the text.
    h.os.state().reads.clear();
    h.local_copy(&[
        ("text/plain;charset=utf-8", b"hunter2"),
        ("text/plain", b"hunter2"),
        (MIME_PASSWORD_HINT, b"secret"),
    ]);
    let msgs = h.take();
    assert_eq!(msgs.len(), 1);
    assert!(initiate_copy(&msgs).is_empty(), "the earlier announcement is retracted with an empty list");

    // The server asks anyway (it still knows the format from the earlier announcement).
    for format in [ClipboardFormatId::CF_UNICODETEXT, HTML_FORMAT_ID, ClipboardFormatId::CF_DIB] {
        h.backend.on_format_data_request(FormatDataRequest { format });
        h.pump();
        assert_eq!(format_data(h.take()), None, "{format:?}");
    }
    let reads = h.os.state().reads.clone();
    assert!(reads.iter().all(|m| m == MIME_PASSWORD_HINT), "the secret itself is never read: {reads:?}");

    // A hint that says anything else does not hide the selection.
    h.local_copy(&[("text/plain;charset=utf-8", b"visible"), (MIME_PASSWORD_HINT, b"public")]);
    assert_eq!(initiate_copy(&h.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);
    h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
    h.pump();
    assert_eq!(format_data(h.take()).expect("data"), convert::text_to_cf_unicodetext("visible"));

    // A hint that is advertised but cannot be read counts as secret.
    {
        let mut s = h.os.state();
        s.mimes = vec!["text/plain".to_owned(), MIME_PASSWORD_HINT.to_owned()];
        s.data = [("text/plain".to_owned(), b"pw".to_vec())].into_iter().collect();
    }
    h.tx.send(Command::LocalChanged).expect("send");
    h.pump();
    assert!(initiate_copy(&h.take()).is_empty());
}

#[test]
fn secret_on_the_clipboard_at_connect_is_not_announced() {
    let mut h = Harness::new(true, 1 << 20);
    {
        let mut s = h.os.state();
        s.mimes = vec!["text/plain;charset=utf-8".to_owned(), MIME_PASSWORD_HINT.to_owned()];
        s.data = [
            ("text/plain;charset=utf-8".to_owned(), b"hunter2".to_vec()),
            (MIME_PASSWORD_HINT.to_owned(), b"secret".to_vec()),
        ]
        .into_iter()
        .collect();
    }
    let msgs = h.connect();
    assert_eq!(msgs.len(), 1);
    assert!(initiate_copy(&msgs).is_empty());
    h.backend.on_format_data_request(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT });
    h.pump();
    assert_eq!(format_data(h.take()), None);
}

#[test]
fn secret_files_are_not_offered() {
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    let src = tempfile::tempdir().expect("tmp");
    let f = src.path().join("keys.kdbx");
    std::fs::write(&f, b"db").expect("write");
    h.local_copy(&[("text/uri-list", &uri::build_uri_list(&[f])), (MIME_PASSWORD_HINT, b"secret")]);
    assert!(initiate_copy(&h.take()).is_empty());
    assert!(file_contents(&mut h, range(1, 0, 0, 16, None)).is_error());
}

/// Puts what session `from` offers on the (shared) local clipboard as seen by session `to`.
fn share_selection(from: &Harness, to: &mut Harness) {
    let offered = from.os.state().offered.clone();
    assert!(!offered.is_empty(), "the source session owns the selection");
    let items: Vec<(&str, &[u8])> =
        offered.iter().map(|o| (o.mime.as_str(), o.data.as_deref().unwrap_or_default())).collect();
    to.local_copy(&items);
}

#[test]
fn remote_offers_carry_the_session_marker() {
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
    let offered = h.os.state().offered.clone();
    let marker = offered.iter().find(|o| o.mime == MIME_BASTION_REMOTE).expect("marker offered");
    assert!(marker.data.is_some(), "the marker is answered without asking the remote");
    // Nothing to offer: the local clipboard is left alone, marker included.
    let mut h = Harness::new(true, 1 << 20);
    h.connect();
    h.remote_copy(&[ClipboardFormat::new(ClipboardFormatId(0xC123))]);
    assert!(h.os.state().offered.is_empty());
}

#[test]
fn another_sessions_remote_clipboard_is_not_re_exported() {
    let mut a = Harness::new(true, 1 << 20);
    a.connect();
    let mut b = Harness::new(true, 1 << 20);
    b.connect();
    b.local_copy(&[("text/plain;charset=utf-8", b"mine")]);
    assert_eq!(initiate_copy(&b.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);

    // Server A copies text, HTML and an image; session A offers them locally.
    a.remote_copy(&[
        ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
        ClipboardFormat::new(CF_HTML_REMOTE).with_name(ClipboardFormatName::HTML),
        ClipboardFormat::new(ClipboardFormatId::CF_DIB),
    ]);
    b.os.state().reads.clear();
    share_selection(&a, &mut b);
    let msgs = b.take();
    assert_eq!(msgs.len(), 1);
    assert!(initiate_copy(&msgs).is_empty(), "session B announces nothing (and retracts its earlier list)");
    for format in [ClipboardFormatId::CF_UNICODETEXT, HTML_FORMAT_ID, ClipboardFormatId::CF_DIB] {
        b.backend.on_format_data_request(FormatDataRequest { format });
        b.pump();
        assert_eq!(format_data(b.take()), None, "server B cannot pull server A's data");
    }
    assert!(b.os.state().reads.is_empty(), "session B never reads session A's offer");
    assert!(a.take().is_empty(), "so session A fetches nothing from its server");

    // The same when session B connects while session A's offer is on the clipboard.
    let mut c = Harness::new(true, 1 << 20);
    {
        let offered = a.os.state().offered.clone();
        c.os.state().mimes = offered.iter().map(|o| o.mime.clone()).collect();
    }
    let msgs = c.connect();
    assert!(initiate_copy(&msgs).is_empty());
    assert!(msgs.iter().all(|m| matches!(m, ClipboardMessage::SendInitiateCopy(_))));

    // An ordinary local copy afterwards is announced as before.
    b.local_copy(&[("text/plain;charset=utf-8", b"typed")]);
    assert_eq!(initiate_copy(&b.take()), vec![ClipboardFormatId::CF_UNICODETEXT]);
}

#[test]
fn another_sessions_remote_files_are_neither_downloaded_nor_re_exported() {
    let mut a = Harness::new(true, 4 << 20);
    a.connect();
    let mut b = Harness::new(true, 4 << 20);
    b.connect();
    a.remote_copy(&[ClipboardFormat::new(FILE_LIST_REMOTE).with_name(ClipboardFormatName::FILE_LIST)]);
    a.take();

    // Session B sees session A's file offer: it must not read the list (which would make A
    // download the files with no paste anywhere).
    share_selection(&a, &mut b);
    assert!(initiate_copy(&b.take()).is_empty());
    assert!(b.os.state().reads.is_empty());
    assert!(a.take().is_empty(), "no file list was requested from server A");

    // The user pastes A's files somewhere; later a clipboard manager re-publishes their paths
    // without the marker. Session B (which never downloaded anything itself) recognises them.
    let rx = a.paste("text/uri-list");
    a.take();
    let (files, contents) = remote_files();
    a.backend.on_remote_file_list(&files, None);
    a.pump();
    serve_download(&mut a, &contents, None);
    let list = delivered(&rx).expect("uri list");
    assert!(!uri::parse_uri_list(&list).is_empty());
    b.local_copy(&[("text/uri-list", &list)]);
    let msgs = b.take();
    assert!(
        msgs.iter().all(|m| !matches!(m, ClipboardMessage::SendInitiateFileCopy(_))),
        "another session's downloads are not uploaded: {msgs:?}"
    );
    assert!(file_contents(&mut b, range(1, 0, 0, 16, None)).is_error());
}

// ---------------------------------------------------------------------------------------------
// End to end through the real `CliprdrClient`, with the test playing the RDP server.
// ---------------------------------------------------------------------------------------------

mod e2e {
    use ironrdp_cliprdr::CliprdrClient;
    use ironrdp_cliprdr::pdu::{
        Capabilities, ClipboardPdu, ClipboardProtocolVersion, FormatList, FormatListResponse, OwnedFormatDataResponse,
        PackedFileList,
    };
    use ironrdp_svc::{SvcMessage, SvcProcessor as _};

    use super::*;

    struct Wire {
        h: Harness,
        client: CliprdrClient,
    }

    impl Wire {
        fn new(max: usize) -> Self {
            let h = Harness::new(true, max);
            let factory =
                BackendFactory { commands: h.tx.clone(), files: true, max_transfer_bytes: max, flow: h.flow.shared() };
            let client = CliprdrClient::new(factory.build_cliprdr_backend());
            let mut w = Self { h, client };
            w.h.pump();
            w
        }

        fn encode(msgs: Vec<SvcMessage>) -> Vec<Vec<u8>> {
            msgs.iter().map(|m| m.encode_unframed_pdu().expect("encode")).collect()
        }

        /// Runs the worker and routes its messages into the client like the session engine
        /// does. Returns the encoded PDUs the client sends to the server.
        fn settle(&mut self) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            loop {
                self.h.pump();
                let msgs = self.h.take();
                if msgs.is_empty() {
                    return out;
                }
                for msg in msgs {
                    let result = match msg {
                        ClipboardMessage::SendInitiateCopy(f) => self.client.initiate_copy(&f),
                        ClipboardMessage::SendInitiateFileCopy(f) => self.client.initiate_file_copy(f),
                        ClipboardMessage::SendFormatData(r) => self.client.submit_format_data(r),
                        ClipboardMessage::SendInitiatePaste(id) => self.client.initiate_paste(id),
                        ClipboardMessage::SendFileContentsRequest(r) => self.client.request_file_contents(r),
                        ClipboardMessage::SendFileContentsResponse(r) => self.client.submit_file_contents(r),
                        ClipboardMessage::Error(e) => panic!("unexpected clipboard error: {e}"),
                    };
                    out.extend(Self::encode(result.expect("cliprdr accepts the message").into()));
                }
            }
        }

        /// Server -> client PDU; returns everything the client sends back (directly or after
        /// the worker reacted).
        fn server(&mut self, pdu: &ClipboardPdu<'_>) -> Vec<Vec<u8>> {
            let bytes = ironrdp_core::encode_vec(pdu).expect("encode server pdu");
            let mut out = Self::encode(self.client.process(&bytes).expect("client processes pdu"));
            out.extend(self.settle());
            out
        }
    }

    fn decode(bytes: &[u8]) -> ClipboardPdu<'_> {
        ironrdp_core::decode::<ClipboardPdu<'_>>(bytes).expect("decode client pdu")
    }

    fn connect(w: &mut Wire) {
        let caps = Capabilities::new(
            ClipboardProtocolVersion::V2,
            ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES | file_capabilities(),
        );
        assert!(w.server(&ClipboardPdu::Capabilities(caps)).is_empty());
        let out = w.server(&ClipboardPdu::MonitorReady);
        let kinds: Vec<&str> = out.iter().map(|b| decode(b).message_name()).collect();
        assert_eq!(kinds.len(), 3, "capabilities + temporary directory + format list: {kinds:?}");
        assert!(matches!(decode(&out[2]), ClipboardPdu::FormatList(_)));
        assert!(w.server(&ClipboardPdu::FormatListResponse(FormatListResponse::Ok)).is_empty());
        assert!(w.client.is_ready());
    }

    #[test]
    fn text_both_ways() {
        let mut w = Wire::new(1 << 20);
        connect(&mut w);

        // Local copy -> FormatList -> server requests CF_UNICODETEXT.
        w.h.local_copy(&[("text/plain;charset=utf-8", b"hello\nrdp")]);
        let out = w.settle();
        let ClipboardPdu::FormatList(list) = decode(&out[0]) else { panic!("format list") };
        let formats = list.get_formats(true).expect("formats");
        assert_eq!(formats[0].id(), ClipboardFormatId::CF_UNICODETEXT);
        assert!(w.server(&ClipboardPdu::FormatListResponse(FormatListResponse::Ok)).is_empty());
        let out =
            w.server(&ClipboardPdu::FormatDataRequest(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT }));
        let ClipboardPdu::FormatDataResponse(resp) = decode(&out[0]) else { panic!("data") };
        assert_eq!(resp.to_unicode_string().expect("utf16"), "hello\r\nrdp");

        // Server copy -> offered locally -> paste -> FormatDataRequest -> response -> local data.
        let list =
            FormatList::new_unicode(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)], true).expect("list");
        let out = w.server(&ClipboardPdu::FormatList(list));
        assert!(matches!(decode(&out[0]), ClipboardPdu::FormatListResponse(FormatListResponse::Ok)));
        assert!(w.h.os.state().owner);
        let rx = w.h.paste("text/plain;charset=utf-8");
        let out = w.settle();
        assert!(matches!(
            decode(&out[0]),
            ClipboardPdu::FormatDataRequest(FormatDataRequest { format: ClipboardFormatId::CF_UNICODETEXT })
        ));
        let response = OwnedFormatDataResponse::new_unicode_string("from\r\nserver");
        w.server(&ClipboardPdu::FormatDataResponse(response));
        assert_eq!(delivered(&rx).expect("data"), b"from\nserver");
    }

    #[test]
    fn files_both_ways() {
        let mut w = Wire::new(4 << 20);
        connect(&mut w);

        // Upload: local file -> FileGroupDescriptorW -> server reads it.
        let src = tempfile::tempdir().expect("tmp");
        let f = src.path().join("upload.txt");
        std::fs::write(&f, b"uploaded bytes").expect("write");
        w.h.local_copy(&[("text/uri-list", &uri::build_uri_list(&[f]))]);
        let out = w.settle();
        let ClipboardPdu::FormatList(list) = decode(&out[0]) else { panic!("format list") };
        let formats = list.get_formats(true).expect("formats");
        let file_format = formats
            .iter()
            .find(|f| f.name.as_ref().is_some_and(|n| n.value() == "FileGroupDescriptorW"))
            .expect("file list format")
            .id();
        w.server(&ClipboardPdu::FormatListResponse(FormatListResponse::Ok));
        let out = w.server(&ClipboardPdu::FormatDataRequest(FormatDataRequest { format: file_format }));
        let ClipboardPdu::FormatDataResponse(resp) = decode(&out[0]) else { panic!("data") };
        let files = resp.to_file_list().expect("file list").files;
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "upload.txt");
        assert_eq!(files[0].file_size, Some(14));
        let out = w.server(&ClipboardPdu::FileContentsRequest(FileContentsRequest {
            stream_id: 3,
            index: 0,
            flags: FileContentsFlags::RANGE,
            position: 9,
            requested_size: 100,
            data_id: None,
        }));
        let ClipboardPdu::FileContentsResponse(resp) = decode(&out[0]) else { panic!("contents") };
        assert_eq!((resp.stream_id(), resp.data()), (3, &b"bytes"[..]));

        // Download: server copies files -> local paste -> file list -> contents -> URIs.
        let remote_id = ClipboardFormatId(0xC0AB);
        let list =
            FormatList::new_unicode(&[ClipboardFormat::new(remote_id).with_name(ClipboardFormatName::FILE_LIST)], true)
                .expect("list");
        let out = w.server(&ClipboardPdu::FormatList(list));
        let lock = out.iter().find_map(|b| match decode(b) {
            ClipboardPdu::LockData(id) => Some(id.0),
            _ => None,
        });
        assert!(lock.is_some(), "client locks the server clipboard (CAN_LOCK_CLIPDATA)");
        let rx = w.h.paste("text/uri-list");
        let out = w.settle();
        assert!(
            matches!(decode(&out[0]), ClipboardPdu::FormatDataRequest(FormatDataRequest { format }) if format == remote_id)
        );

        let remote = PackedFileList {
            files: vec![
                FileDescriptor::new("sub\\inner.txt")
                    .with_attributes(ClipboardFileAttributes::ARCHIVE)
                    .with_file_size(6),
                FileDescriptor::new("..\\..\\evil.txt")
                    .with_attributes(ClipboardFileAttributes::ARCHIVE)
                    .with_file_size(4),
            ],
        };
        let response = OwnedFormatDataResponse::new_file_list(&remote).expect("encode list");
        let mut out = w.server(&ClipboardPdu::FormatDataResponse(response));
        let contents: [&[u8]; 2] = [b"inside", b"evil"];
        while let Some(bytes) = out.pop() {
            let ClipboardPdu::FileContentsRequest(req) = decode(&bytes) else { continue };
            assert_eq!(req.data_id, lock);
            let data = contents[usize::try_from(req.index).expect("index")];
            let start = usize::try_from(req.position).expect("pos");
            let end = (start + req.requested_size as usize).min(data.len());
            let resp = FileContentsResponse::new_data_response(req.stream_id, &data[start..end]);
            out.extend(w.server(&ClipboardPdu::FileContentsResponse(resp)));
        }
        let paths = uri::parse_uri_list(&delivered(&rx).expect("uris"));
        // Cliprdr strips the traversal ("evil.txt" lands at the root); nothing escapes the root.
        assert!(paths.iter().all(|p| p.starts_with(w.h.base.path())), "{paths:?}");
        let root = paths[0].parent().expect("download dir").to_owned();
        assert_eq!(std::fs::read(root.join("sub/inner.txt")).expect("read"), b"inside");
        assert!(!w.h.base.path().join("evil.txt").exists());
    }
}

// ---------------------------------------------------------------------------------------------
// Real Wayland data-control (opt-in: replaces the session clipboard while it runs).
// ---------------------------------------------------------------------------------------------

/// Run with `BASTION_TEST_REAL_CLIPBOARD=1 cargo test -p bastion-clipboard real_wayland`.
#[test]
fn real_wayland_delayed_rendering_round_trip() {
    use ironrdp_cliprdr_native::data_control::DataControl;

    if std::env::var_os("BASTION_TEST_REAL_CLIPBOARD").is_none_or(|v| v != "1")
        || std::env::var_os("WAYLAND_DISPLAY").is_none()
    {
        eprintln!("skipping: set BASTION_TEST_REAL_CLIPBOARD=1 in a Wayland session to run");
        return;
    }
    let (tx, rx) = mpsc::channel();
    let mut ours = match crate::os::wayland::WaylandClipboard::open(tx, 1 << 20) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skipping: data-control unavailable: {e}");
            return;
        }
    };
    let reader = DataControl::connect().expect("second data-control client");
    let previous = reader.read("text/plain;charset=utf-8").ok().flatten();

    ours.offer(&[OfferItem::delayed("text/plain;charset=utf-8")], 1).expect("offer");
    let answerer = std::thread::spawn(move || {
        while let Ok(cmd) = rx.recv_timeout(Duration::from_secs(5)) {
            if let Command::Paste(t) = cmd {
                assert_eq!(t.generation(), 1);
                t.finish(Some(b"bastion real clipboard test".to_vec()));
                return true;
            }
        }
        false
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while reader.selection_mime_types().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let got = reader.read("text/plain;charset=utf-8").expect("read").expect("offered");
    assert_eq!(got, b"bastion real clipboard test");
    assert!(answerer.join().expect("join"), "the paste reached the worker channel");

    // Best effort restore of the user's text clipboard.
    if let Some(prev) = previous {
        use ironrdp_cliprdr_native::data_control::Content;
        let _ = reader.set_selection(Content::new().data("text/plain;charset=utf-8", prev));
        std::thread::sleep(Duration::from_millis(200));
    }
}
