//! UI tests: drive the real egui UI headlessly (clicks, typing) and compare rendered snapshots.
//!
//! Update reference images after an intentional UI change with:
//!   UPDATE_SNAPSHOTS=1 cargo test -p bastion --test ui

use std::sync::{Arc, Mutex};

use bastion::manager::Manager;
use bastion::session::{Action, certificate_dialog, disconnected_card};
use bastion_core::AppPaths;
use bastion_core::store::ProfileStore;
use bastion_core::trust::{EndpointKind, TrustStore};
use bastion_session::tls::CertificateRejection;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable as _;

struct Fixture {
    _dir: tempfile::TempDir,
    paths: AppPaths,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let paths = AppPaths::rooted(dir.path());
    Fixture { _dir: dir, paths }
}

fn manager(f: &Fixture) -> Manager {
    Manager::new(f.paths.clone(), Arc::new(Mutex::new(TrustStore::in_memory())), Arc::new(|| {})).unwrap()
}

fn harness(m: Manager) -> Harness<'static, Manager> {
    Harness::builder().with_size(egui::vec2(1000.0, 680.0)).wgpu().build_ui_state(
        |ui, m: &mut Manager| {
            bastion::theme::apply(ui.ctx());
            let _ = m.ui(ui);
        },
        m,
    )
}

fn text_inputs(h: &Harness<'_, Manager>) -> usize {
    h.query_all_by_role(egui::accesskit::Role::TextInput).count()
}

#[test]
fn empty_state_welcomes_user() {
    let f = fixture();
    let mut h = harness(manager(&f));
    h.run();
    h.get_by_label("Welcome to Bastion");
    h.get_by_label("+  New connection");
    h.snapshot("manager_empty");
}

#[test]
fn create_and_save_connection_through_the_ui() {
    let f = fixture();
    let mut h = harness(manager(&f));
    h.run();
    h.get_by_label("+  New connection").click();
    h.run();
    h.get_by_label("New connection");

    // Inputs in order: search, name, computer, port, username, domain, folder.
    let before = text_inputs(&h);
    assert!(before >= 6, "editor should show its fields, found {before}");
    let mut inputs: Vec<_> = h.query_all_by_role(egui::accesskit::Role::TextInput).collect();
    inputs[1].focus();
    inputs[1].type_text("Work PC");
    h.run();
    inputs = h.query_all_by_role(egui::accesskit::Role::TextInput).collect();
    inputs[2].focus();
    inputs[2].type_text("pc01.corp.local");
    h.run();

    // Enable the gateway.
    h.get_by_label("Connect through a Remote Desktop Gateway").click();
    h.run();
    h.get_by_label("Use the same credentials for the gateway and the computer");
    // Saving now must fail: gateway enabled but no gateway host.
    h.get_by_label("Save").click();
    h.run();
    h.get_by_label("Gateway host is required when a gateway is enabled.");
    let gw = h.get_by_role_and_label(egui::accesskit::Role::TextInput, "Gateway");
    gw.focus();
    gw.type_text("rdg.corp.com");
    h.run();
    h.snapshot("editor_general_with_gateway");

    h.get_by_label("Save").click();
    h.run();
    h.get_by_label("Saved Work PC.");

    let store = ProfileStore::load(&f.paths).unwrap();
    let p = &store.profiles()[0];
    assert_eq!(p.name, "Work PC");
    assert_eq!(p.host, "pc01.corp.local");
    assert_eq!(p.gateway.as_ref().unwrap().host, "rdg.corp.com");
    assert!(!p.drive.enabled, "drive sharing must default to off");
}

#[test]
fn keep_active_interval_is_chosen_in_editor_and_saved() {
    let f = fixture();
    let mut h = harness(manager(&f));
    h.run();
    h.get_by_label("+  New connection").click();
    h.run();
    let inputs: Vec<_> = h.query_all_by_role(egui::accesskit::Role::TextInput).collect();
    inputs[2].focus();
    inputs[2].type_text("pc01");
    h.run();

    h.get_by_label("Security & advanced").click();
    h.run();
    h.get_by_label("Move mouse").click();
    h.run();
    h.get_by_label("After 5 minutes idle").click();
    h.run();
    h.snapshot("editor_advanced_keep_active");

    h.get_by_label("Save").click();
    h.run();
    let store = ProfileStore::load(&f.paths).unwrap();
    assert_eq!(store.profiles()[0].keep_active, bastion_core::profile::KeepActive::Min5);
}

#[test]
fn webcam_sharing_is_off_by_default_and_can_be_enabled() {
    let f = fixture();
    let mut h = harness(manager(&f));
    h.run();
    h.get_by_label("+  New connection").click();
    h.run();
    let inputs: Vec<_> = h.query_all_by_role(egui::accesskit::Role::TextInput).collect();
    inputs[2].focus();
    inputs[2].type_text("pc01");
    h.run();

    // No snapshot: this tab lists the machine's real audio devices.
    h.get_by_label("Audio & devices").click();
    h.run();
    // One click turns it on, so it started off.
    h.get_by_label("Use this computer's webcams in the remote session").click();
    h.run();

    h.get_by_label("Save").click();
    h.run();
    assert!(ProfileStore::load(&f.paths).unwrap().profiles()[0].camera.enabled);
}

#[test]
fn saving_without_computer_shows_validation_error() {
    let f = fixture();
    let mut h = harness(manager(&f));
    h.run();
    h.get_by_label("+  New connection").click();
    h.run();
    h.get_by_label("Save").click();
    h.run();
    h.get_by_label("Computer (host) is required.");
    assert!(ProfileStore::load(&f.paths).unwrap().profiles().is_empty());
}

#[test]
fn imported_rdp_file_opens_in_editor_with_warnings() {
    let f = fixture();
    let rdp = f.paths.config_dir.join("work.rdp");
    std::fs::create_dir_all(&f.paths.config_dir).unwrap();
    std::fs::write(
        &rdp,
        "full address:s:pc01.corp.local\r\nusername:s:CORP\\alice\r\ngatewayhostname:s:rdg.corp.com\r\ngatewayusagemethod:i:1\r\ndrivestoredirect:s:*\r\n",
    )
    .unwrap();
    let mut m = manager(&f);
    m.import_file(&rdp);
    let mut h = harness(m);
    h.run();
    h.get_by_label("New connection");
    assert!(h.query_by_label_contains("drive redirection").is_some(), "warn that drives were left off");
    h.snapshot("editor_imported");
    h.get_by_label("Save").click();
    h.run();
    let store = ProfileStore::load(&f.paths).unwrap();
    assert_eq!(store.profiles()[0].gateway.as_ref().unwrap().host, "rdg.corp.com");
}

#[test]
fn connecting_without_saved_password_prompts_for_credentials() {
    let f = fixture();
    let mut store = ProfileStore::load(&f.paths).unwrap();
    let p = bastion_core::Profile {
        name: "Lab".into(),
        host: "lab01".into(),
        username: "bob".into(),
        ..Default::default()
    };
    store.upsert(p.clone()).unwrap();
    let mut m = manager(&f);
    assert!(m.begin_connect(p.id).is_none(), "no stored password → must prompt");
    let mut h = harness(m);
    h.run();
    h.get_by_label("Sign in to Lab");
    h.snapshot("credential_prompt");
    // Submitting with an empty password is refused (the modal's Connect is the last one).
    h.get_all_by_label("Connect").last().unwrap().click();
    h.run();
    h.get_by_label("Enter a username and password.");
}

fn rejection(previous: Option<&str>) -> CertificateRejection {
    CertificateRejection {
        kind: EndpointKind::Rdp,
        endpoint: "pc01.corp.local:3389".into(),
        der: vec![],
        fingerprint: "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
            .into(),
        reason: "invalid peer certificate: UnknownIssuer".into(),
        previous_fingerprint: previous.map(str::to_owned),
        subject: "CN=pc01.corp.local".into(),
        issuer: "CN=pc01.corp.local".into(),
        not_after: "2027-05-01 00:00:00 UTC".into(),
    }
}

struct DialogState {
    rej: CertificateRejection,
    ack: bool,
    actions: Vec<Action>,
}

fn cert_harness(previous: Option<&str>) -> Harness<'static, DialogState> {
    Harness::builder().with_size(egui::vec2(800.0, 560.0)).wgpu().build_ui_state(
        |ui, s: &mut DialogState| {
            bastion::theme::apply(ui.ctx());
            certificate_dialog(ui, &s.rej, &mut s.ack, &mut s.actions);
        },
        DialogState { rej: rejection(previous), ack: false, actions: Vec::new() },
    )
}

#[test]
fn first_use_certificate_can_be_trusted() {
    let mut h = cert_harness(None);
    h.run();
    h.get_by_label("Verify the remote identity");
    h.snapshot("cert_first_use");
    h.get_by_label("Trust and connect").click();
    h.run();
    assert_eq!(h.state().actions, vec![Action::TrustCert(true)]);
}

#[test]
fn changed_certificate_requires_explicit_acknowledgement() {
    let mut h = cert_harness(Some("00:11:22:33"));
    h.run();
    h.get_by_label("⚠  The certificate has CHANGED");
    h.snapshot("cert_changed");
    // Button is disabled until the user ticks the acknowledgement.
    h.get_by_label("Replace and connect").click();
    h.run();
    assert!(h.state().actions.is_empty(), "must not trust a changed certificate without acknowledgement");
    h.get_by_label("I have verified the new certificate and want to replace the old one").click();
    h.run();
    h.get_by_label("Replace and connect").click();
    h.run();
    assert_eq!(h.state().actions, vec![Action::TrustCert(true)]);
}

#[test]
fn disconnect_card_offers_reconnect() {
    let mut h = Harness::builder().with_size(egui::vec2(700.0, 420.0)).wgpu().build_ui_state(
        |ui, actions: &mut Vec<Action>| {
            bastion::theme::apply(ui.ctx());
            disconnected_card(ui, "Work PC", "Sign-in failed: the username or password is incorrect.", true, actions);
        },
        Vec::new(),
    );
    h.run();
    h.snapshot("disconnected_error");
    h.get_by_label("Reconnect").click();
    h.run();
    assert_eq!(h.state(), &vec![Action::Reconnect]);
}

fn quality(level: bastion::quality::Level, latency: f32) -> bastion::quality::Quality {
    bastion::quality::Quality {
        level,
        latency_ms: Some(latency),
        latency_source: Some(bastion::quality::LatencySource::Gateway),
        jitter_ms: Some(1.5),
        loss_pct: Some(0.2),
        fps: 30.0,
        down_mbps: 12.3,
        up_mbps: 0.25,
        capacity_mbps: None,
        via_gateway: true,
    }
}

#[test]
fn session_bar_shows_connection_details_on_hover() {
    let mut h = Harness::builder().with_size(egui::vec2(900.0, 360.0)).wgpu().build_ui_state(
        |ui, actions: &mut Vec<Action>| {
            bastion::theme::apply(ui.ctx());
            ui.ctx().global_style_mut(|s| s.interaction.tooltip_delay = 0.0);
            let q = quality(bastion::quality::Level::Poor, 230.0);
            let _ = bastion::session::session_bar(ui, "Work PC", Some(&q), true, true, actions);
        },
        Vec::new(),
    );
    h.run();
    h.get_by_label("230 ms").hover();
    h.run();
    h.get_by_label("Connection: Poor");
    h.get_by_label("Round trip to the RD Gateway");
    h.get_by_label("12.3 Mbit/s");
    h.get_by_label("Through RD Gateway");
    h.snapshot("session_bar_quality");
}

#[test]
fn session_bar_offers_minimise() {
    let mut h = Harness::builder().with_size(egui::vec2(900.0, 120.0)).wgpu().build_ui_state(
        |ui, actions: &mut Vec<Action>| {
            bastion::theme::apply(ui.ctx());
            let q = quality(bastion::quality::Level::Good, 12.0);
            let _ = bastion::session::session_bar(ui, "Work PC", Some(&q), true, true, actions);
        },
        Vec::new(),
    );
    h.run();
    h.snapshot("session_bar");
    h.get_by_label("Minimise").click();
    h.run();
    assert_eq!(h.state(), &vec![Action::Minimize]);
}

#[test]
fn multi_monitor_mode_can_use_selected_monitors() {
    let f = fixture();
    let mut m = manager(&f);
    m.set_monitor_list(vec![
        ("DP-1".into(), "DP-1 — 3840 × 2160".into()),
        ("DP-2".into(), "DP-2 — 2560 × 1440".into()),
        ("HDMI-A-1".into(), "HDMI-A-1 — 1920 × 1080".into()),
    ]);
    let mut h = harness(m);
    h.run();
    h.get_by_label("+  New connection").click();
    h.run();
    let inputs: Vec<_> = h.query_all_by_role(egui::accesskit::Role::TextInput).collect();
    inputs[2].focus();
    inputs[2].type_text("pc01");
    h.run();

    h.get_by_label("Display").click();
    h.run();
    h.get_by_label("Full screen on multiple monitors").click();
    h.run();
    // All monitors by default; unticking "all" lists them, all ticked.
    h.get_by_label("Use all monitors").click();
    h.run();
    h.get_by_label("DP-2 — 2560 × 1440").click();
    h.run();
    h.snapshot("editor_display_monitor_selection");

    h.get_by_label("Save").click();
    h.run();
    let store = ProfileStore::load(&f.paths).unwrap();
    let p = &store.profiles()[0];
    assert_eq!(p.display.mode, bastion_core::profile::DisplayMode::AllMonitors);
    assert_eq!(p.display.monitors, vec!["DP-1".to_owned(), "HDMI-A-1".to_owned()]);
}

#[test]
fn new_monitor_prompt_offers_multiple_monitors() {
    let labels = vec!["DP-2 — 2560 × 1440".to_owned()];
    let mut h = Harness::builder().with_size(egui::vec2(700.0, 300.0)).wgpu().build_ui_state(
        move |ui, actions: &mut Vec<Action>| {
            bastion::theme::apply(ui.ctx());
            let _ = bastion::session::monitor_prompt(ui, &labels, actions);
        },
        Vec::new(),
    );
    h.run();
    h.snapshot("monitor_prompt");
    h.get_by_label("Use multiple monitors").click();
    h.run();
    h.get_by_label("Not now").click();
    h.run();
    assert_eq!(h.state(), &vec![Action::UseNewMonitors, Action::DismissNewMonitors]);
}

#[test]
fn wake_on_lan_mac_is_entered_validated_and_saved() {
    let f = fixture();
    let mut h = harness(manager(&f));
    h.run();
    h.get_by_label("+  New connection").click();
    h.run();
    let inputs: Vec<_> = h.query_all_by_role(egui::accesskit::Role::TextInput).collect();
    inputs[2].focus();
    inputs[2].type_text("pc01");
    h.run();

    h.get_by_label("MAC address").focus();
    h.get_by_label("MAC address").type_text("00-11-22");
    h.run();
    h.get_by_label("Save").click();
    h.run();
    assert!(h.query_by_label_contains("Wake-on-LAN: \"00-11-22\" is not a MAC address").is_some());
    assert!(ProfileStore::load(&f.paths).unwrap().profiles().is_empty());

    h.get_by_label("MAC address").focus();
    h.get_by_label("MAC address").type_text("-33-44-55");
    h.run();
    h.snapshot("editor_general_wake_on_lan");
    h.get_by_label("Save").click();
    h.run();
    let store = ProfileStore::load(&f.paths).unwrap();
    let p = &store.profiles()[0];
    assert_eq!(p.wake.mac, "00-11-22-33-44-55");
    assert!(p.wake.on_connect, "waking on connect is on by default once a MAC is set");
}

#[test]
fn wake_button_sends_the_magic_packet() {
    let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    rx.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
    let f = fixture();
    let mut store = ProfileStore::load(&f.paths).unwrap();
    let mut p = bastion_core::Profile { name: "Desktop".into(), host: "desktop".into(), ..Default::default() };
    p.wake.mac = "00:11:22:33:44:55".into();
    p.wake.broadcast = "127.0.0.1".into();
    p.wake.port = rx.local_addr().unwrap().port();
    store.upsert(p).unwrap();
    let mut h = harness(manager(&f));
    h.run();
    assert!(h.query_by_label_contains("00:11:22:33:44:55, wakes automatically").is_some());
    h.get_by_label("Wake").click();
    h.run();
    let mut buf = [0u8; 200];
    let n = rx.recv(&mut buf).expect("magic packet");
    let mac = "00:11:22:33:44:55".parse().unwrap();
    assert_eq!(&buf[..n], &bastion_core::wol::magic_packet(mac));
    assert!(h.query_by_label_contains("Wake-up packet sent to Desktop").is_some());
    h.snapshot("details_wake_sent");
}
