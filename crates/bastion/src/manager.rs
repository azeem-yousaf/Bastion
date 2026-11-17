//! Connection manager window: saved connections, editor, import, credentials, settings.

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};

use bastion_core::profile::{DisplayMode, GatewaySettings, KeepActive, Profile};
use bastion_core::secrets::{self, Secret, SecretKind};
use bastion_core::store::{AppSettings, ProfileStore};
use bastion_core::trust::TrustStore;
use bastion_core::{AppPaths, rdpfile};
use uuid::Uuid;

use crate::theme;

pub struct ConnectRequest {
    pub profile: Profile,
    pub password: Secret,
    pub gateway_password: Option<Secret>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    General,
    Display,
    Devices,
    Advanced,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Connections,
    Settings,
}

enum Pick {
    ImportRdp,
    ShareFolder,
}

struct CredPrompt {
    profile: Profile,
    password: Secret,
    gateway_user: String,
    gateway_password: Secret,
    remember: bool,
    error: Option<String>,
    /// Wipes freed memory while the prompt is open: egui's copies of what is typed. Declared
    /// last so it outlives the other fields when the prompt is dropped.
    _wipe: crate::wipe::WipeScope,
}

/// Largest file accepted as an `.rdp` file (the same bound `rdpfile::decode_text` applies to the
/// decoded bytes). Real ones are a few kilobytes.
pub const MAX_RDP_FILE_BYTES: u64 = 1024 * 1024;

/// Reads an `.rdp` file without trusting what the path points at: it must be a regular file of
/// at most [`MAX_RDP_FILE_BYTES`], checked on the opened file *before* anything is read, and the
/// read itself is capped. A device (`/dev/zero`), a FIFO, a directory or a huge/sparse file is
/// refused instead of exhausting memory or blocking the UI thread.
pub fn read_rdp_file(path: &std::path::Path) -> anyhow::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    // Checked before opening too: opening a device has side effects of its own (a serial port
    // resets the board on it), and opening a FIFO releases a writer waiting on it.
    if !std::fs::metadata(path).map_err(|e| anyhow::anyhow!("{}", friendly_io_error(&e)))?.is_file() {
        anyhow::bail!("it is not a regular file");
    }
    // Non-blocking so that opening a FIFO (swapped in after the check) returns at once instead
    // of waiting for a writer; it has no effect on regular files. The opened file is checked
    // again below.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| anyhow::anyhow!("{}", friendly_io_error(&e)))?;
    let meta = file.metadata().map_err(|e| anyhow::anyhow!("{}", friendly_io_error(&e)))?;
    if !meta.is_file() {
        anyhow::bail!("it is not a regular file");
    }
    if meta.len() > MAX_RDP_FILE_BYTES {
        anyhow::bail!("file is too large to be an .rdp file");
    }
    // The size can change after the check (or be misreported): never read past the cap.
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_RDP_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow::anyhow!("{}", friendly_io_error(&e)))?;
    if bytes.len() as u64 > MAX_RDP_FILE_BYTES {
        anyhow::bail!("file is too large to be an .rdp file");
    }
    Ok(bytes)
}

fn friendly_io_error(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::NotFound => "the file does not exist",
        std::io::ErrorKind::PermissionDenied => "you do not have permission to read it",
        _ => "the file could not be read",
    }
}

/// The start of a certificate fingerprint for the trusted-hosts list. Counts characters, not
/// bytes: the value comes from `known_hosts.toml` and need not be the ASCII hex Bastion writes.
pub fn short_fingerprint(fp: &str) -> String {
    let mut short: String = fp.chars().take(23).collect();
    short.push('…');
    short
}

/// Drops egui's undo history for a password field. egui records the full text of every
/// `TextEdit` (masked or not) there, and keeps it for as long as the window exists.
fn scrub_secret_field(ctx: &egui::Context, id: egui::Id) {
    if let Some(mut state) = egui::TextEdit::load_state(ctx, id) {
        state.clear_undoer();
        state.store(ctx, id);
    }
}

/// Removes everything egui remembers about a password field once the prompt is closed.
fn forget_secret_field(ctx: &egui::Context, id: egui::Id) {
    scrub_secret_field(ctx, id);
    ctx.data_mut(|d| d.remove::<egui::text_edit::TextEditState>(id));
}

/// Room reserved for a typed password, so that typing does not reallocate the buffer and leave
/// un-wiped prefixes of the password behind on the heap.
const SECRET_CAPACITY: usize = 256;

fn empty_secret() -> Secret {
    Secret::new(String::with_capacity(SECRET_CAPACITY))
}

pub struct Manager {
    paths: AppPaths,
    store: ProfileStore,
    pub settings: AppSettings,
    trust: Arc<Mutex<TrustStore>>,
    page: Page,
    selected: Option<Uuid>,
    draft: Option<Profile>,
    draft_is_new: bool,
    tab: Tab,
    search: String,
    prompt: Option<CredPrompt>,
    banner: Option<(String, bool)>,
    import_warnings: Vec<String>,
    picker: Option<(Pick, Receiver<Option<PathBuf>>)>,
    devices: Option<Receiver<anyhow::Result<bastion_audio::DeviceList>>>,
    device_list: Option<bastion_audio::DeviceList>,
    confirm_delete: bool,
    waker: Arc<dyn Fn() + Send + Sync>,
    keyring_ok: bool,
    /// Connected monitors (key, label) for the multi-monitor selection.
    monitors: Vec<(String, String)>,
    /// Wake-on-LAN MAC address detection running in the background.
    detect_mac: Option<Receiver<Result<bastion_core::wol::MacAddr, String>>>,
    /// egui ids of the credential prompt's password fields as last drawn.
    secret_fields: Vec<egui::Id>,
    /// A `.rdp` file from a later launch, waiting for the connection being edited to be closed.
    pending_import: Option<PathBuf>,
}

impl Manager {
    pub fn new(
        paths: AppPaths,
        trust: Arc<Mutex<TrustStore>>,
        waker: Arc<dyn Fn() + Send + Sync>,
    ) -> anyhow::Result<Self> {
        let store = ProfileStore::load(&paths)?;
        let settings = AppSettings::load(&paths);
        let selected = store.profiles().first().map(|p| p.id);
        Ok(Self {
            paths,
            store,
            settings,
            trust,
            page: Page::Connections,
            selected,
            draft: None,
            draft_is_new: false,
            tab: Tab::General,
            search: String::new(),
            prompt: None,
            banner: None,
            import_warnings: Vec::new(),
            picker: None,
            devices: None,
            device_list: None,
            confirm_delete: false,
            waker,
            keyring_ok: secrets::keyring_available(),
            monitors: Vec::new(),
            detect_mac: None,
            secret_fields: Vec::new(),
            pending_import: None,
        })
    }

    /// Updates the list of connected monitors offered in the display settings.
    pub fn set_monitors(&mut self, screens: &[crate::monitors::Screen]) {
        self.set_monitor_list(screens.iter().map(|s| (s.key.clone(), s.label.clone())).collect());
    }

    /// Same as [`Self::set_monitors`] from plain (key, label) pairs (used by tests).
    pub fn set_monitor_list(&mut self, monitors: Vec<(String, String)>) {
        self.monitors = monitors;
        (self.waker)();
    }

    pub fn profile(&self, id: Uuid) -> Option<&Profile> {
        self.store.profiles().iter().find(|p| p.id == id)
    }

    /// Imports a .rdp file given on the command line / via file association.
    pub fn import_file(&mut self, path: &std::path::Path) {
        match read_rdp_file(path).and_then(|b| rdpfile::decode_text(&b)) {
            Ok(text) => {
                let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                let (p, warnings) = rdpfile::import(&text, &name);
                self.import_warnings = warnings;
                self.draft = Some(p);
                self.draft_is_new = true;
                self.tab = Tab::General;
                self.page = Page::Connections;
                let file =
                    path.file_name().map_or_else(|| path.display().to_string(), |f| f.to_string_lossy().into_owned());
                self.banner = Some((format!("Imported {file}. Review the settings and save."), false));
            }
            Err(e) => self.banner = Some((format!("Could not import {}: {e}", path.display()), true)),
        }
    }

    /// Imports a .rdp file opened while Bastion was already running. Unlike the user's own
    /// "Import" or "New connection" click, this arrives unasked, so a connection being edited
    /// with unsaved changes is kept: the file waits until that edit is saved or cancelled.
    pub fn import_launched(&mut self, path: &std::path::Path) {
        if !self.draft_has_changes() {
            self.import_file(path);
            return;
        }
        let file = path.file_name().map_or_else(|| path.display().to_string(), |f| f.to_string_lossy().into_owned());
        self.banner =
            Some((format!("{file} will open for import when you save or cancel the connection being edited."), false));
        self.pending_import = Some(path.to_path_buf());
    }

    /// Opens a waiting [`Self::import_launched`] file once nothing is being edited.
    fn apply_pending_import(&mut self) {
        if self.draft.is_none()
            && let Some(path) = self.pending_import.take()
        {
            self.import_file(&path);
        }
    }

    /// A connection is being edited and differs from what is saved (any new one counts).
    fn draft_has_changes(&self) -> bool {
        self.draft.as_ref().is_some_and(|d| self.draft_is_new || self.profile(d.id) != Some(d))
    }

    /// Cancels the credential prompt, if open (e.g. its window was closed). Call
    /// [`Self::forget_secret_fields`] first, while egui's state of it still exists.
    pub fn cancel_prompt(&mut self) {
        self.prompt = None;
    }

    /// Opens the credential prompt (or connects straight away with a stored password).
    pub fn begin_connect(&mut self, id: Uuid) -> Option<ConnectRequest> {
        // Another Bastion process may have changed this profile (e.g. its security settings).
        self.reload_profiles();
        let p = self.profile(id)?.clone();
        let needs_gw = p.gateway.as_ref().is_some_and(|g| !g.same_credentials);
        if p.security.remember_password && self.keyring_ok {
            let host = secrets::load(p.id, SecretKind::Host).ok().flatten();
            let gw = if needs_gw { secrets::load(p.id, SecretKind::Gateway).ok().flatten() } else { None };
            if let Some(password) = host
                && (!needs_gw || gw.is_some())
            {
                return Some(ConnectRequest { profile: p, password, gateway_password: gw });
            }
        }
        let gateway_user = p.gateway.as_ref().map(|g| g.username.clone()).unwrap_or_default();
        self.prompt = Some(CredPrompt {
            remember: p.security.remember_password && self.keyring_ok,
            profile: p,
            password: empty_secret(),
            gateway_user,
            gateway_password: empty_secret(),
            error: None,
            _wipe: crate::wipe::WipeScope::begin(),
        });
        None
    }

    /// Picks up profiles saved by another Bastion process (one `stat` when nothing changed).
    fn reload_profiles(&mut self) {
        if let Err(e) = self.store.reload() {
            tracing::warn!(error = %e, "Could not re-read the saved connections");
        }
    }

    /// egui ids of the credential prompt's password fields, as last drawn (used by tests to
    /// check that nothing about them is left in egui's memory).
    pub fn password_field_ids(&self) -> &[egui::Id] {
        &self.secret_fields
    }

    fn pick(&mut self, kind: Pick) {
        let (tx, rx) = channel();
        let waker = self.waker.clone();
        let is_folder = matches!(kind, Pick::ShareFolder);
        std::thread::spawn(move || {
            let d = rfd::FileDialog::new();
            let r = if is_folder {
                d.set_title("Choose a folder to share").pick_folder()
            } else {
                d.set_title("Import .rdp file").add_filter("Remote Desktop file", &["rdp"]).pick_file()
            };
            let _ = tx.send(r);
            waker();
        });
        self.picker = Some((kind, rx));
    }

    fn poll_background(&mut self) {
        if let Some((_, rx)) = &self.picker
            && let Ok(result) = rx.try_recv()
        {
            let (kind, _) = self.picker.take().expect("picker present");
            if let Some(path) = result {
                match kind {
                    Pick::ImportRdp => self.import_file(&path),
                    Pick::ShareFolder => {
                        if let Some(d) = self.draft.as_mut() {
                            d.drive.local_path = path.to_string_lossy().into_owned();
                        }
                    }
                }
            }
        }
        if let Some(rx) = &self.detect_mac
            && let Ok(r) = rx.try_recv()
        {
            self.detect_mac = None;
            match (r, self.draft.as_mut()) {
                (Ok(mac), Some(d)) => d.wake.mac = mac.to_string(),
                (Ok(_), None) => {}
                (Err(e), _) => self.banner = Some((e, true)),
            }
        }
        if let Some(rx) = &self.devices
            && let Ok(r) = rx.try_recv()
        {
            self.devices = None;
            match r {
                Ok(list) => self.device_list = Some(list),
                Err(e) => self.banner = Some((format!("Could not list audio devices: {e}"), true)),
            }
        }
    }

    fn start_mac_detection(&mut self, host: String, port: u16) {
        let (tx, rx) = channel();
        let waker = self.waker.clone();
        std::thread::spawn(move || {
            let _ = tx.send(bastion_core::wol::detect_mac(&host, port));
            waker();
        });
        self.detect_mac = Some(rx);
    }

    /// Remembers whether the session bar is pinned (changed from a session's bar).
    pub fn set_pin_session_bar(&mut self, pinned: bool) {
        if self.settings.pin_session_bar != pinned {
            self.settings.pin_session_bar = pinned;
            if let Err(e) = self.settings.save(&self.paths) {
                tracing::warn!(error = %e, "Could not save settings");
            }
        }
    }

    /// Sends the Wake-on-LAN packet for a saved connection.
    pub fn wake(&mut self, id: Uuid) {
        let Some(p) = self.profile(id) else { return };
        let name = p.display_name().to_owned();
        self.banner = Some(match p.wake.configured() {
            None => ("Set the computer's MAC address first (Edit → General → Wake-on-LAN).".into(), true),
            Some((mac, to)) => match bastion_core::wol::send(mac, to) {
                Ok(()) => {
                    tracing::info!(%mac, %to, "Sent Wake-on-LAN");
                    (format!("Wake-up packet sent to {name}. It may take a minute to start."), false)
                }
                Err(e) => (format!("Could not send the wake-up packet: {e}"), true),
            },
        });
    }

    fn load_devices(&mut self) {
        if self.device_list.is_some() || self.devices.is_some() {
            return;
        }
        let (tx, rx) = channel();
        let waker = self.waker.clone();
        std::thread::spawn(move || {
            let _ = tx.send(bastion_audio::list_devices());
            waker();
        });
        self.devices = Some(rx);
    }

    /// Draws the manager. Returns a connection request when the user starts one.
    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<ConnectRequest> {
        self.poll_background();
        self.reload_profiles();
        self.apply_pending_import();
        let mut request = None;

        egui::Panel::left("connections").resizable(true).default_size(270.0).show(ui, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                theme::logo(ui, 24.0);
                ui.heading("Bastion");
            });
            ui.add_space(6.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text("Search connections…")
                    .desired_width(f32::INFINITY),
            );
            ui.add_space(4.0);
            egui::ScrollArea::vertical().auto_shrink([false, false]).max_height(ui.available_height() - 120.0).show(
                ui,
                |ui| {
                    let q = self.search.to_lowercase();
                    let mut profiles: Vec<Profile> = self
                        .store
                        .profiles()
                        .iter()
                        .filter(|p| {
                            q.is_empty()
                                || p.display_name().to_lowercase().contains(&q)
                                || p.host.to_lowercase().contains(&q)
                        })
                        .cloned()
                        .collect();
                    profiles.sort_by(|a, b| {
                        (a.group.to_lowercase(), a.display_name().to_lowercase())
                            .cmp(&(b.group.to_lowercase(), b.display_name().to_lowercase()))
                    });
                    let mut last_group = None::<String>;
                    for p in profiles {
                        if !p.group.is_empty() && last_group.as_deref() != Some(&p.group) {
                            theme::section(ui, &p.group);
                            last_group = Some(p.group.clone());
                        }
                        let selected = self.selected == Some(p.id) && self.page == Page::Connections;
                        let resp = connection_row(ui, &p, selected);
                        if resp.clicked() {
                            self.selected = Some(p.id);
                            self.draft = None;
                            self.page = Page::Connections;
                            self.confirm_delete = false;
                        }
                        if resp.double_clicked() {
                            request = self.begin_connect(p.id);
                        }
                    }
                },
            );
            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.add_space(8.0);
                if ui.add(egui::Button::new("⚙  Settings & trusted hosts").frame(false)).clicked() {
                    self.page = Page::Settings;
                }
                if ui.add_sized([ui.available_width(), 30.0], egui::Button::new("Import .rdp file…")).clicked() {
                    self.pick(Pick::ImportRdp);
                }
                if ui
                    .add_sized(
                        [ui.available_width(), 32.0],
                        egui::Button::new(egui::RichText::new("+  New connection").strong())
                            .fill(theme::ACCENT.linear_multiply(0.35)),
                    )
                    .clicked()
                {
                    let mut p = Profile::default();
                    p.security.remember_password = self.keyring_ok;
                    self.draft = Some(p);
                    self.draft_is_new = true;
                    self.tab = Tab::General;
                    self.page = Page::Connections;
                    self.import_warnings.clear();
                }
            });
        });

        egui::CentralPanel::default_margins().show(ui, |ui| {
            if let Some((msg, err)) = self.banner.clone() {
                banner(ui, &msg, err, &mut self.banner);
            }
            match self.page {
                Page::Settings => self.settings_page(ui),
                Page::Connections => {
                    if self.draft.is_some() {
                        self.editor(ui);
                    } else if let Some(p) = self.selected.and_then(|id| self.profile(id)).cloned() {
                        if let Some(r) = self.details(ui, &p) {
                            request = Some(r);
                        }
                    } else {
                        empty_state(ui);
                    }
                }
            }
        });

        if let Some(r) = self.prompt_ui(ui) {
            request = Some(r);
        }
        request
    }

    fn details(&mut self, ui: &mut egui::Ui, p: &Profile) -> Option<ConnectRequest> {
        let mut request = None;
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading(p.display_name());
                ui.label(egui::RichText::new(format!("{}:{}", p.host, p.port)).color(theme::MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::primary_button(ui, "Connect").clicked() {
                    request = self.begin_connect(p.id);
                }
                if p.wake.configured().is_some()
                    && ui.button("Wake").on_hover_text("Send a Wake-on-LAN packet to switch the computer on").clicked()
                {
                    self.wake(p.id);
                }
                if ui.button("Edit").clicked() {
                    self.draft = Some(p.clone());
                    self.draft_is_new = false;
                    self.tab = Tab::General;
                    self.import_warnings.clear();
                }
            });
        });
        ui.separator();
        egui::Grid::new("summary").num_columns(2).spacing([24.0, 8.0]).show(ui, |ui| {
            let mut row = |k: &str, v: String| {
                ui.label(egui::RichText::new(k).color(theme::MUTED));
                ui.label(v);
                ui.end_row();
            };
            row("User", if p.username.is_empty() { "(ask when connecting)".into() } else { p.qualified_username() });
            row("Gateway", p.gateway.as_ref().map_or("Direct connection".into(), |g| g.endpoint()));
            row(
                "Display",
                match p.display.mode {
                    DisplayMode::Window => {
                        format!("Window{}", if p.display.dynamic_resolution { ", resizes remote desktop" } else { "" })
                    }
                    DisplayMode::Fullscreen => "Full screen".into(),
                    DisplayMode::AllMonitors if p.display.monitors.is_empty() => "Full screen on all monitors".into(),
                    DisplayMode::AllMonitors => format!("Full screen on {}", p.display.monitors.join(", ")),
                },
            );
            row(
                "Audio",
                match (p.audio.playback, p.audio.microphone) {
                    (true, true) => "Speakers and microphone".into(),
                    (true, false) => "Speakers".into(),
                    (false, true) => "Microphone".into(),
                    (false, false) => "Off".into(),
                },
            );
            row(
                "Clipboard",
                if p.clipboard.enabled {
                    if p.clipboard.files { "Text, images and files" } else { "Text and images" }
                } else {
                    "Off"
                }
                .into(),
            );
            row(
                "Shared folder",
                if p.drive.enabled {
                    format!("{} → \"{}\"", p.drive.local_path, p.drive.share_name)
                } else {
                    "None".into()
                },
            );
            row(
                "Wake-on-LAN",
                match p.wake.configured() {
                    None => "Off".into(),
                    Some((mac, _)) if p.wake.on_connect => format!("{mac}, wakes automatically when connecting"),
                    Some((mac, _)) => mac.to_string(),
                },
            );
            if p.security.allow_insecure_tls {
                ui.label(egui::RichText::new("Security").color(theme::MUTED));
                ui.label(egui::RichText::new("⚠ Certificate checks disabled").color(theme::DANGER));
                ui.end_row();
            }
        });
        request
    }

    fn editor(&mut self, ui: &mut egui::Ui) {
        let keyring_ok = self.keyring_ok;
        let mut save = false;
        let mut cancel = false;
        let mut delete = false;
        let mut pick_folder = false;
        let mut want_devices = false;
        let mut detect = false;
        let detecting = self.detect_mac.is_some();
        let devices = self.device_list.clone();
        let is_new = self.draft_is_new;
        let mut confirm_delete = self.confirm_delete;
        let warnings = self.import_warnings.clone();
        let tab = &mut self.tab;
        let Some(d) = self.draft.as_mut() else { return };

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading(if is_new { "New connection" } else { "Edit connection" });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::primary_button(ui, "Save").clicked() {
                    save = true;
                }
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
                if !is_new {
                    if confirm_delete {
                        if theme::danger_button(ui, "Confirm delete").clicked() {
                            delete = true;
                        }
                    } else if ui.button("Delete").clicked() {
                        confirm_delete = true;
                    }
                }
            });
        });
        for w in &warnings {
            ui.label(egui::RichText::new(format!("Note: {w}")).color(theme::WARN));
        }
        ui.horizontal(|ui| {
            for (t, label) in [
                (Tab::General, "General"),
                (Tab::Display, "Display"),
                (Tab::Devices, "Audio & devices"),
                (Tab::Advanced, "Security & advanced"),
            ] {
                ui.selectable_value(tab, t, label);
            }
        });
        ui.separator();

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match *tab {
            Tab::General => {
                form(ui, "general", |ui| {
                    field(ui, "Name", |ui| ui.add(egui::TextEdit::singleline(&mut d.name).hint_text("e.g. Work PC")));
                    field(ui, "Computer", |ui| ui.add(egui::TextEdit::singleline(&mut d.host).hint_text("pc01.corp.local")));
                    field(ui, "Port", |ui| ui.add(egui::DragValue::new(&mut d.port).range(1..=65535)));
                    field(ui, "Username", |ui| ui.add(egui::TextEdit::singleline(&mut d.username).hint_text("alice")));
                    field(ui, "Domain", |ui| ui.add(egui::TextEdit::singleline(&mut d.domain).hint_text("CORP (optional)")));
                    field(ui, "Folder", |ui| ui.add(egui::TextEdit::singleline(&mut d.group).hint_text("Optional group name")));
                });
                theme::section(ui, "RD Gateway");
                let mut use_gw = d.gateway.is_some();
                if ui.checkbox(&mut use_gw, "Connect through a Remote Desktop Gateway").changed() {
                    d.gateway = use_gw.then(GatewaySettings::default);
                }
                if let Some(gw) = d.gateway.as_mut() {
                    form(ui, "gw", |ui| {
                        field(ui, "Gateway", |ui| ui.add(egui::TextEdit::singleline(&mut gw.host).hint_text("rdg.example.com")));
                        field(ui, "Port", |ui| ui.add(egui::DragValue::new(&mut gw.port).range(1..=65535)));
                    });
                    ui.checkbox(&mut gw.same_credentials, "Use the same credentials for the gateway and the computer");
                    if !gw.same_credentials {
                        form(ui, "gwcreds", |ui| {
                            field(ui, "Gateway user", |ui| ui.add(egui::TextEdit::singleline(&mut gw.username)));
                            field(ui, "Gateway domain", |ui| ui.add(egui::TextEdit::singleline(&mut gw.domain)));
                        });
                    }
                }
                theme::section(ui, "Sign-in");
                ui.add_enabled(keyring_ok, egui::Checkbox::new(&mut d.security.remember_password, "Remember password in the system keyring"))
                    .on_disabled_hover_text("No Secret Service (KWallet / GNOME Keyring) is available");
                theme::section(ui, "Wake-on-LAN");
                form(ui, "wake", |ui| {
                    field(ui, "MAC address", |ui| {
                        ui.horizontal(|ui| {
                            let mac = ui.add(
                                egui::TextEdit::singleline(&mut d.wake.mac).hint_text("Off — e.g. 00:11:22:33:44:55").desired_width(220.0),
                            );
                            let can_detect = !detecting && !d.host.trim().is_empty();
                            let label = if detecting { "Detecting…" } else { "Detect" };
                            if ui
                                .add_enabled(can_detect, egui::Button::new(label))
                                .on_hover_text("Look up the MAC address of the computer (it must be switched on and on this network)")
                                .clicked()
                            {
                                detect = true;
                            }
                            mac
                        })
                        .inner
                    });
                });
                ui.add_enabled_ui(!d.wake.mac.trim().is_empty(), |ui| {
                    ui.checkbox(&mut d.wake.on_connect, "Wake the computer when connecting if it doesn't answer");
                    egui::CollapsingHeader::new("Broadcast address").id_salt("wake-advanced").show(ui, |ui| {
                        form(ui, "wake-adv", |ui| {
                            field(ui, "Send to", |ui| {
                                ui.add(egui::TextEdit::singleline(&mut d.wake.broadcast).hint_text("255.255.255.255 (this network)"))
                            });
                            field(ui, "UDP port", |ui| ui.add(egui::DragValue::new(&mut d.wake.port).range(1..=65535)));
                        });
                    });
                });
                ui.label(
                    egui::RichText::new(
                        "Switches the computer on from sleep or off. Works on the computer's local network, with Wake-on-LAN enabled in its BIOS/UEFI and network adapter.",
                    )
                    .small()
                    .color(theme::MUTED),
                );
            }
            Tab::Display => {
                theme::section(ui, "Mode");
                ui.radio_value(&mut d.display.mode, DisplayMode::Window, "Window");
                ui.radio_value(&mut d.display.mode, DisplayMode::Fullscreen, "Full screen");
                ui.radio_value(&mut d.display.mode, DisplayMode::AllMonitors, "Full screen on multiple monitors");
                if d.display.mode == DisplayMode::AllMonitors {
                    monitor_selection(ui, &mut d.display.monitors, &self.monitors);
                }
                if d.display.mode == DisplayMode::Window {
                    form(ui, "size", |ui| {
                        field(ui, "Initial width", |ui| ui.add(egui::DragValue::new(&mut d.display.width).range(640..=8192)));
                        field(ui, "Initial height", |ui| ui.add(egui::DragValue::new(&mut d.display.height).range(480..=8192)));
                    });
                }
                ui.checkbox(&mut d.display.dynamic_resolution, "Resize the remote desktop when the window is resized");
                ui.checkbox(&mut d.display.follow_local_scale, "Use this computer's display scaling (HiDPI)");
                theme::section(ui, "Performance");
                ui.checkbox(&mut d.display.h264, "H.264 video codec (lower bandwidth, smoother video)");
                ui.add_enabled(d.display.h264, egui::Checkbox::new(&mut d.display.hardware_decode, "Hardware decoding (NVDEC / VAAPI) when software can't keep up"))
                    .on_hover_text("Remote-desktop video usually decodes faster on the CPU; the graphics card takes over for heavy video");
            }
            Tab::Devices => {
                want_devices = true;
                theme::section(ui, "Audio");
                ui.checkbox(&mut d.audio.playback, "Play remote audio on this computer");
                ui.add_enabled_ui(d.audio.playback, |ui| {
                    device_combo(ui, "out", "Output", &mut d.audio.output_device, devices.as_ref().map(|l| &l.outputs[..]));
                    form(ui, "lat", |ui| {
                        field(ui, "Buffer", |ui| ui.add(egui::Slider::new(&mut d.audio.playback_latency_ms, 20..=500).suffix(" ms")))
                            .on_hover_text("Lower = less delay; raise it if audio crackles on slow networks");
                    });
                });
                ui.checkbox(&mut d.audio.microphone, "Use this computer's microphone in the remote session");
                ui.add_enabled_ui(d.audio.microphone, |ui| {
                    device_combo(ui, "in", "Microphone", &mut d.audio.input_device, devices.as_ref().map(|l| &l.inputs[..]));
                });
                theme::section(ui, "Camera");
                ui.checkbox(&mut d.camera.enabled, "Use this computer's webcams in the remote session");
                ui.label(
                    egui::RichText::new("All webcams are offered; the remote computer turns one on only when an app uses it.")
                        .small()
                        .color(theme::MUTED),
                );
                theme::section(ui, "Clipboard");
                ui.checkbox(&mut d.clipboard.enabled, "Share the clipboard (text, rich text, images)");
                ui.add_enabled_ui(d.clipboard.enabled, |ui| {
                    ui.checkbox(&mut d.clipboard.files, "Allow copying files through the clipboard");
                    form(ui, "cliplimit", |ui| {
                        field(ui, "Max transfer", |ui| ui.add(egui::Slider::new(&mut d.clipboard.max_transfer_mb, 1..=1024).suffix(" MB")));
                    });
                });
                theme::section(ui, "Shared folder");
                ui.checkbox(&mut d.drive.enabled, "Share a local folder with the remote computer");
                ui.add_enabled_ui(d.drive.enabled, |ui| {
                    form(ui, "drive", |ui| {
                        // Label the text box itself (not the row) so screen readers name it.
                        field(ui, "Folder", |ui| {
                            ui.horizontal(|ui| {
                                let path = ui.add(egui::TextEdit::singleline(&mut d.drive.local_path).desired_width(260.0));
                                if ui.button("Browse…").clicked() {
                                    pick_folder = true;
                                }
                                path
                            })
                            .inner
                        });
                        field(ui, "Shown as", |ui| ui.add(egui::TextEdit::singleline(&mut d.drive.share_name)));
                    });
                    ui.checkbox(&mut d.drive.read_only, "Read-only (the remote computer cannot change or delete files)");
                    let note = if d.drive.read_only {
                        "The remote computer can open and copy files from this folder, but not modify it."
                    } else {
                        "The remote computer can read, change and delete files in this folder. Only share what you need."
                    };
                    ui.label(egui::RichText::new(note).small().color(theme::MUTED));
                });
            }
            Tab::Advanced => {
                theme::section(ui, "Reconnection");
                ui.checkbox(&mut d.reconnect.enabled, "Reconnect automatically if the network drops");
                form(ui, "rc", |ui| {
                    field(ui, "Attempts", |ui| ui.add(egui::DragValue::new(&mut d.reconnect.max_attempts).range(1..=100)));
                });
                theme::section(ui, "Keep session active");
                form(ui, "keepactive", |ui| {
                    field(ui, "Move mouse", |ui| {
                        egui::ComboBox::from_id_salt("keep_active")
                            .selected_text(d.keep_active.label())
                            .show_ui(ui, |ui| {
                                for k in KeepActive::ALL {
                                    ui.selectable_value(&mut d.keep_active, k, k.label());
                                }
                            })
                            .response
                    })
                    .on_hover_text("Nudges the remote mouse by one pixel when you haven't used the session for a while");
                });
                ui.label(
                    egui::RichText::new("Keeps the remote computer from locking and apps like Teams showing you as Away.")
                        .small()
                        .color(theme::MUTED),
                );
                theme::section(ui, "Danger zone");
                ui.checkbox(&mut d.security.allow_insecure_tls, egui::RichText::new("Skip certificate verification (insecure)").color(theme::DANGER));
                if d.security.allow_insecure_tls {
                    ui.label(
                        egui::RichText::new("Anyone on the network path could impersonate the gateway or computer and capture your password. Use only in isolated labs.")
                            .color(theme::DANGER)
                            .small(),
                    );
                }
            }
        });

        self.confirm_delete = confirm_delete;
        if want_devices {
            self.load_devices();
        }
        if pick_folder {
            self.pick(Pick::ShareFolder);
        }
        if detect && let Some(d) = self.draft.as_ref() {
            let (host, port) = (d.host.trim().to_owned(), d.port);
            self.start_mac_detection(host, port);
        }
        if cancel {
            self.draft = None;
            self.import_warnings.clear();
        }
        if delete {
            if let Some(d) = self.draft.take() {
                let _ = secrets::delete_all(d.id);
                if let Err(e) = self.store.remove(d.id) {
                    self.banner = Some((format!("Could not delete: {e}"), true));
                }
                self.selected = self.store.profiles().first().map(|p| p.id);
            }
            self.confirm_delete = false;
        }
        if save && let Some(d) = self.draft.as_ref() {
            let problems = d.validate();
            if !problems.is_empty() {
                self.banner = Some((problems.join(" "), true));
                return;
            }
            let mut p = d.clone();
            p.host = p.host.trim().to_owned();
            if !p.security.remember_password {
                let _ = secrets::delete_all(p.id);
            }
            match self.store.upsert(p.clone()) {
                Ok(()) => {
                    self.selected = Some(p.id);
                    self.draft = None;
                    self.import_warnings.clear();
                    self.banner = Some((format!("Saved {}.", p.display_name()), false));
                }
                Err(e) => self.banner = Some((format!("Could not save: {e}"), true)),
            }
        }
    }

    fn settings_page(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Settings");
        ui.separator();
        theme::section(ui, "Keyboard");
        ui.label(format!("Release keyboard / show session bar: {}", self.settings.release_chord));
        let mut grab = self.settings.grab_system_shortcuts;
        if ui
            .checkbox(&mut grab, "Send system shortcuts (Alt+Tab, Super) to the remote computer while it has focus")
            .changed()
        {
            self.settings.grab_system_shortcuts = grab;
            if let Err(e) = self.settings.save(&self.paths) {
                self.banner = Some((format!("Could not save settings: {e}"), true));
            }
        }

        theme::section(ui, "Trusted certificates");
        ui.label(
            egui::RichText::new("Certificates you approved for gateways and computers. Remove one to be asked again.")
                .small()
                .color(theme::MUTED),
        );
        let entries: Vec<(String, String, String)> = self
            .trust
            .lock()
            .map(|mut t| {
                // Shows pins another Bastion process added or forgot (one `stat` if unchanged).
                let _ = t.reload();
                t.entries().map(|(k, p)| (k.to_owned(), p.sha256.clone(), p.pinned_at.clone())).collect()
            })
            .unwrap_or_default();
        let mut forget = None;
        egui::Grid::new("pins").striped(true).num_columns(3).spacing([16.0, 6.0]).show(ui, |ui| {
            for (key, fp, at) in &entries {
                let (kind, endpoint) = key.split_once('|').unwrap_or(("", key));
                ui.label(format!("{endpoint} ({kind})"));
                ui.label(egui::RichText::new(short_fingerprint(fp)).monospace().small()).on_hover_text(fp);
                if ui.small_button("Forget").on_hover_text(format!("Trusted {at}")).clicked() {
                    forget = Some((kind.to_owned(), endpoint.to_owned()));
                }
                ui.end_row();
            }
        });
        if entries.is_empty() {
            ui.label(egui::RichText::new("None yet.").color(theme::MUTED));
        }
        if let Some((kind, endpoint)) = forget {
            let kind = if kind == "gateway" {
                bastion_core::trust::EndpointKind::Gateway
            } else {
                bastion_core::trust::EndpointKind::Rdp
            };
            if let Ok(mut t) = self.trust.lock() {
                let _ = t.forget(kind, &endpoint);
            }
        }

        theme::section(ui, "Diagnostics");
        let logs = self.paths.log_dir();
        ui.horizontal(|ui| {
            ui.label(format!("Logs: {}", logs.display()));
            if ui.button("Open folder").clicked() {
                let _ = std::process::Command::new("xdg-open").arg(&logs).spawn();
            }
        });
        ui.label(
            egui::RichText::new("Logs never contain passwords or keystrokes. Nothing is sent anywhere.")
                .small()
                .color(theme::MUTED),
        );
        theme::section(ui, "About");
        ui.label(format!("Bastion {}", env!("CARGO_PKG_VERSION")));
    }

    fn prompt_ui(&mut self, ui: &mut egui::Ui) -> Option<ConnectRequest> {
        let keyring_ok = self.keyring_ok;
        let p = self.prompt.as_mut()?;
        let mut submit = false;
        let mut cancel = false;
        let needs_gw = p.profile.gateway.as_ref().is_some_and(|g| !g.same_credentials);
        let caps = bastion_session::keyboard::read_lock_state().caps;
        let mut secret_fields = Vec::new();

        egui::Modal::new(egui::Id::unique("cred")).show(ui.ctx(), |ui| {
            ui.set_width(380.0);
            ui.heading(format!("Sign in to {}", p.profile.display_name()));
            ui.label(egui::RichText::new(&p.profile.host).color(theme::MUTED));
            ui.add_space(8.0);
            form(ui, "credform", |ui| {
                field(ui, "Username", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut p.profile.username).hint_text("user"))
                });
                field(ui, "Domain", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut p.profile.domain).hint_text("optional"))
                });
                let r = field(ui, "Password", |ui| {
                    ui.add(egui::TextEdit::singleline(p.password.as_mut_string()).password(true))
                });
                // No undo history for passwords: egui would keep plain copies of every state.
                scrub_secret_field(ui.ctx(), r.id);
                secret_fields.push(r.id);
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submit = true;
                }
                if !p.profile.username.is_empty() && p.password.is_empty() && !needs_gw {
                    r.request_focus();
                }
                if needs_gw {
                    field(ui, "Gateway user", |ui| ui.add(egui::TextEdit::singleline(&mut p.gateway_user)));
                    let r = field(ui, "Gateway password", |ui| {
                        ui.add(egui::TextEdit::singleline(p.gateway_password.as_mut_string()).password(true))
                    });
                    scrub_secret_field(ui.ctx(), r.id);
                    secret_fields.push(r.id);
                }
            });
            if caps {
                ui.label(egui::RichText::new("Caps Lock is on").color(theme::WARN));
            }
            if let Some(e) = &p.error {
                ui.label(egui::RichText::new(e).color(theme::DANGER));
            }
            ui.add_enabled(keyring_ok, egui::Checkbox::new(&mut p.remember, "Remember password"));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if theme::primary_button(ui, "Connect").clicked() {
                    submit = true;
                }
                if ui.button("Cancel").clicked() || ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    cancel = true;
                }
            });
        });

        self.secret_fields = secret_fields;
        if cancel {
            // egui's field state first, while the prompt's wipe scope is still alive; dropping the
            // prompt then wipes both passwords (`Secret` zeroizes on drop).
            self.forget_secret_fields(ui.ctx());
            self.prompt = None;
            return None;
        }
        if !submit {
            return None;
        }
        if p.profile.username.trim().is_empty() || p.password.is_empty() {
            p.error = Some("Enter a username and password.".into());
            return None;
        }
        let mut prompt = self.prompt.take()?;
        self.forget_secret_fields(ui.ctx());
        if let Some(gw) = prompt.profile.gateway.as_mut()
            && needs_gw
        {
            gw.username = prompt.gateway_user.clone();
        }
        // Persist username/remember choice (never the password itself) on the profile. Only
        // these fields: the rest of this copy may be older than what another process saved.
        prompt.profile.security.remember_password = prompt.remember;
        let (username, domain, remember) =
            (prompt.profile.username.clone(), prompt.profile.domain.clone(), prompt.remember);
        let gateway_user = needs_gw.then(|| prompt.gateway_user.clone());
        let updated = self.store.update(prompt.profile.id, |p| {
            p.username.clone_from(&username);
            p.domain.clone_from(&domain);
            p.security.remember_password = remember;
            if let (Some(gw), Some(user)) = (p.gateway.as_mut(), &gateway_user) {
                gw.username.clone_from(user);
            }
        });
        if let Ok(Some(current)) = updated {
            // Connect with the settings as saved now.
            prompt.profile = current;
        }
        if prompt.remember {
            if let Err(e) = secrets::store(prompt.profile.id, SecretKind::Host, &prompt.password) {
                self.banner = Some((format!("Password not saved: {e}"), true));
            }
            if needs_gw {
                let _ = secrets::store(prompt.profile.id, SecretKind::Gateway, &prompt.gateway_password);
            }
        }
        // Moved, not copied: the prompt keeps no second copy of either password.
        Some(ConnectRequest {
            password: std::mem::take(&mut prompt.password),
            gateway_password: needs_gw.then(|| std::mem::take(&mut prompt.gateway_password)),
            profile: prompt.profile,
        })
    }

    /// Clears what egui still holds of the prompt's passwords: per-widget state (cursor, undo
    /// history) and this frame's input events, which carry the typed or pasted text and would
    /// otherwise live until the next frame — after the prompt's wipe scope has ended.
    pub fn forget_secret_fields(&self, ctx: &egui::Context) {
        for id in &self.secret_fields {
            forget_secret_field(ctx, *id);
        }
        ctx.input_mut(|i| {
            i.events.clear();
            i.raw.events.clear();
        });
    }

    /// Called when a session fails to sign in, so a stored wrong password is not reused silently.
    pub fn forget_password_after_auth_failure(&mut self, id: Uuid) {
        let _ = secrets::delete(id, SecretKind::Host);
    }
}

fn connection_row(ui: &mut egui::Ui, p: &Profile, selected: bool) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(ui.available_width(), 46.0), egui::Sense::click());
    let painter = ui.painter_at(rect);
    let fill = if selected {
        theme::ACCENT.linear_multiply(0.25)
    } else if resp.hovered() {
        egui::Color32::from_rgb(0x24, 0x29, 0x31)
    } else {
        egui::Color32::TRANSPARENT
    };
    painter.rect_filled(rect, 6.0, fill);
    let x = rect.min.x + 10.0;
    painter.text(
        egui::pos2(x, rect.min.y + 8.0),
        egui::Align2::LEFT_TOP,
        p.display_name(),
        egui::FontId::proportional(14.0),
        ui.visuals().strong_text_color(),
    );
    let sub = match &p.gateway {
        Some(g) => format!("{} via {}", p.host, g.host),
        None => p.host.clone(),
    };
    painter.text(
        egui::pos2(x, rect.min.y + 26.0),
        egui::Align2::LEFT_TOP,
        sub,
        egui::FontId::proportional(12.0),
        theme::MUTED,
    );
    resp.on_hover_text("Double-click to connect")
}

fn form(ui: &mut egui::Ui, id: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::Grid::new(id).num_columns(2).spacing([16.0, 8.0]).min_col_width(110.0).show(ui, add);
}

/// One labelled row. The widget is linked to its label for screen readers.
fn field(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui) -> egui::Response) -> egui::Response {
    let l = ui.label(egui::RichText::new(label).color(theme::MUTED));
    let r = add(ui).labelled_by(l.id);
    ui.end_row();
    r
}

/// Chooses the monitors a multi-monitor session uses. An empty selection means "all".
fn monitor_selection(ui: &mut egui::Ui, selection: &mut Vec<String>, connected: &[(String, String)]) {
    ui.indent("monitors", |ui| {
        let mut all = selection.is_empty();
        if ui.checkbox(&mut all, "Use all monitors").changed() {
            *selection = if all { Vec::new() } else { connected.iter().map(|(k, _)| k.clone()).collect() };
        }
        if all {
            return;
        }
        // Connected monitors, then remembered ones that aren't plugged in right now.
        let mut rows: Vec<(String, String)> = connected.to_vec();
        for k in selection.iter() {
            if !rows.iter().any(|(r, _)| r == k) {
                rows.push((k.clone(), format!("{k} (not connected)")));
            }
        }
        for (key, label) in rows {
            let mut on = selection.contains(&key);
            // The last selected monitor can't be unticked (an empty selection means "all").
            let last = on && selection.len() == 1;
            let resp = ui.add_enabled(!last, egui::Checkbox::new(&mut on, label));
            if resp.changed() {
                if on {
                    selection.push(key);
                } else {
                    selection.retain(|k| *k != key);
                }
            }
        }
        ui.label(
            egui::RichText::new(
                "If a monitor is unplugged the session continues on the others; plugging one in asks first.",
            )
            .small()
            .color(theme::MUTED),
        );
    });
}

fn device_combo(
    ui: &mut egui::Ui,
    id: &str,
    label: &str,
    value: &mut Option<String>,
    devices: Option<&[bastion_audio::AudioDevice]>,
) {
    form(ui, id, |ui| {
        field(ui, label, |ui| {
            let current = match (value.as_ref(), devices) {
                (None, _) => "System default".to_owned(),
                (Some(n), Some(list)) => {
                    list.iter().find(|d| &d.name == n).map_or(n.clone(), |d| d.description.clone())
                }
                (Some(n), None) => n.clone(),
            };
            egui::ComboBox::from_id_salt(id)
                .selected_text(current)
                .width(320.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(value, None, "System default (follows your desktop setting)");
                    match devices {
                        Some(list) => {
                            for d in list {
                                let text = if d.is_default {
                                    format!("{} (current default)", d.description)
                                } else {
                                    d.description.clone()
                                };
                                ui.selectable_value(value, Some(d.name.clone()), text);
                            }
                        }
                        None => {
                            ui.label("Loading devices…");
                        }
                    }
                })
                .response
        });
    });
}

fn banner(ui: &mut egui::Ui, msg: &str, error: bool, slot: &mut Option<(String, bool)>) {
    let colour = if error { theme::DANGER } else { theme::OK };
    egui::Frame::new().fill(colour.linear_multiply(0.15)).corner_radius(6).inner_margin(8).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(msg).color(colour));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("×").clicked() {
                    *slot = None;
                }
            });
        });
    });
}

fn empty_state(ui: &mut egui::Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() / 3.0);
        theme::logo(ui, 64.0);
        ui.heading("Welcome to Bastion");
        ui.label(egui::RichText::new("Create a connection or import an .rdp file to get started.").color(theme::MUTED));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_shortened_by_characters_not_bytes() {
        let ascii = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01";
        assert_eq!(short_fingerprint(ascii), "AB:CD:EF:01:23:45:67:89…");
        assert_eq!(short_fingerprint("AB:CD"), "AB:CD…");
        assert_eq!(short_fingerprint(""), "…");
        // Byte 23 falls inside a multi-byte character: `&fp[..23]` panicked here.
        let odd = "AB:CD:EF:01:23:45:67:8\u{2014}9 \u{201c}renewed\u{201d}";
        assert!(!odd.is_char_boundary(23));
        assert_eq!(short_fingerprint(odd), "AB:CD:EF:01:23:45:67:8\u{2014}…");
        assert_eq!(short_fingerprint(&"é".repeat(40)), format!("{}…", "é".repeat(23)));
    }

    #[test]
    fn rdp_file_is_read_when_small_and_regular() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.rdp");
        std::fs::write(&path, "full address:s:pc01\r\n").unwrap();
        assert_eq!(read_rdp_file(&path).unwrap(), b"full address:s:pc01\r\n");
        // A symlink to a regular file is fine (files are often linked into place).
        let link = dir.path().join("link.rdp");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_rdp_file(&link).unwrap().len(), 21);
        // Exactly at the limit is accepted.
        let edge = dir.path().join("edge.rdp");
        std::fs::write(&edge, vec![b' '; MAX_RDP_FILE_BYTES as usize]).unwrap();
        assert_eq!(read_rdp_file(&edge).unwrap().len() as u64, MAX_RDP_FILE_BYTES);
    }

    #[test]
    fn huge_or_sparse_rdp_file_is_refused_without_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.rdp");
        // 64 GiB sparse: reading it would exhaust memory; the metadata check refuses it at once.
        std::fs::File::create(&path).unwrap().set_len(64 << 30).unwrap();
        let started = std::time::Instant::now();
        let err = read_rdp_file(&path).unwrap_err().to_string();
        assert_eq!(err, "file is too large to be an .rdp file");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let over = dir.path().join("over.rdp");
        std::fs::write(&over, vec![b' '; MAX_RDP_FILE_BYTES as usize + 1]).unwrap();
        assert!(read_rdp_file(&over).is_err());
    }

    #[test]
    fn devices_fifos_and_directories_are_not_rdp_files() {
        let dir = tempfile::tempdir().unwrap();
        // A symlink to an endless device, as shipped inside a hostile archive.
        let zero = dir.path().join("invoice.rdp");
        std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
        assert_eq!(read_rdp_file(&zero).unwrap_err().to_string(), "it is not a regular file");
        // A FIFO with no writer: opening it must not block the (UI) thread.
        let fifo = dir.path().join("pipe.rdp");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(read_rdp_file(&fifo).map_err(|e| e.to_string())));
        let result = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("reading a FIFO must not hang");
        assert_eq!(result.unwrap_err(), "it is not a regular file");
        assert_eq!(read_rdp_file(dir.path()).unwrap_err().to_string(), "it is not a regular file");
        let missing = read_rdp_file(&dir.path().join("missing.rdp")).unwrap_err().to_string();
        assert_eq!(missing, "the file does not exist");
    }

    #[test]
    fn opening_a_non_regular_file_is_avoided_not_just_refused() {
        // Opening a FIFO for reading releases a writer blocked in open(): an observable side
        // effect standing in for a device's (a serial port resets the board on it).
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe.rdp");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let (fifo, opened) = (fifo.clone(), opened.clone());
            std::thread::spawn(move || {
                let f = std::fs::OpenOptions::new().write(true).open(&fifo);
                opened.store(true, std::sync::atomic::Ordering::SeqCst);
                f
            })
        };
        let link = dir.path().join("link.rdp");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();
        // Let the writer reach open() and block there.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(read_rdp_file(&link).unwrap_err().to_string(), "it is not a regular file");
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!opened.load(std::sync::atomic::Ordering::SeqCst), "the FIFO was opened");
        // Release the writer.
        use std::os::unix::fs::OpenOptionsExt as _;
        let _reader = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(&fifo).unwrap();
        writer.join().unwrap().unwrap();
    }

    #[test]
    fn a_launched_import_does_not_discard_unsaved_edits() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let mut m = Manager::new(paths, Arc::new(Mutex::new(TrustStore::in_memory())), Arc::new(|| {})).unwrap();
        let file = dir.path().join("Work PC.rdp");
        std::fs::write(&file, "full address:s:work-pc\r\n").unwrap();

        // A new connection being typed in: kept, and the file waits.
        let typed = Profile { host: "half-typed".into(), ..Default::default() };
        m.draft = Some(typed.clone());
        m.draft_is_new = true;
        m.import_launched(&file);
        assert_eq!(m.draft.as_ref(), Some(&typed));
        assert!(m.banner.as_ref().unwrap().0.contains("Work PC.rdp"));
        m.apply_pending_import();
        assert_eq!(m.draft.as_ref(), Some(&typed));
        // Cancelled: the waiting file opens.
        m.draft = None;
        m.apply_pending_import();
        assert_eq!(m.draft.as_ref().map(|d| d.host.as_str()), Some("work-pc"));
        assert!(m.pending_import.is_none());

        // A saved connection opened for editing but unchanged is simply replaced.
        let saved = Profile { host: "saved".into(), ..Default::default() };
        m.store.upsert(saved.clone()).unwrap();
        m.draft = Some(saved.clone());
        m.draft_is_new = false;
        m.import_launched(&file);
        assert_eq!(m.draft.as_ref().map(|d| d.host.as_str()), Some("work-pc"));
        // ...but kept once changed.
        let mut changed = saved;
        changed.host = "edited".into();
        m.draft = Some(changed.clone());
        m.draft_is_new = false;
        m.import_launched(&file);
        assert_eq!(m.draft.as_ref(), Some(&changed));
    }

    #[test]
    fn importing_an_endless_file_shows_a_friendly_banner() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::rooted(dir.path());
        let mut m = Manager::new(paths, Arc::new(Mutex::new(TrustStore::in_memory())), Arc::new(|| {})).unwrap();
        let zero = dir.path().join("Server.rdp");
        std::os::unix::fs::symlink("/dev/zero", &zero).unwrap();
        m.import_file(&zero);
        let (msg, error) = m.banner.clone().expect("banner");
        assert!(error);
        assert!(msg.starts_with("Could not import ") && msg.ends_with("Server.rdp: it is not a regular file"), "{msg}");
        assert!(m.draft.is_none());
    }
}
