//! Connection profiles: everything needed to (re)establish a session, minus secrets.
//!
//! Secrets (passwords) are never part of a profile; they live in the OS keyring
//! (see [`crate::secrets`]) and are referenced by profile id.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const DEFAULT_RDP_PORT: u16 = 3389;
pub const DEFAULT_GATEWAY_PORT: u16 = 443;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Profile {
    pub id: Uuid,
    /// Human-friendly label shown in the connection manager.
    pub name: String,
    /// Target RDP host (as resolvable *by the gateway* when a gateway is used).
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: String,
    pub gateway: Option<GatewaySettings>,
    pub display: DisplaySettings,
    pub audio: AudioSettings,
    pub clipboard: ClipboardSettings,
    pub drive: DriveSettings,
    pub security: SecuritySettings,
    pub reconnect: ReconnectSettings,
    /// Nudge the remote mouse after this much local inactivity so the remote session (and apps
    /// like Teams) don't go idle/away.
    pub keep_active: KeepActive,
    /// Optional free-form folder/group for organising the connection list.
    pub group: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            host: String::new(),
            port: DEFAULT_RDP_PORT,
            username: String::new(),
            domain: String::new(),
            gateway: None,
            display: DisplaySettings::default(),
            audio: AudioSettings::default(),
            clipboard: ClipboardSettings::default(),
            drive: DriveSettings::default(),
            security: SecuritySettings::default(),
            reconnect: ReconnectSettings::default(),
            keep_active: KeepActive::default(),
            group: String::new(),
        }
    }
}

impl Profile {
    pub fn display_name(&self) -> &str {
        if self.name.trim().is_empty() { &self.host } else { &self.name }
    }

    /// Validates user-entered fields. Returns a list of human-readable problems.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.host.trim().is_empty() {
            problems.push("Computer (host) is required.".to_owned());
        } else if !is_valid_hostname(self.host.trim()) {
            problems.push("Computer name contains invalid characters.".to_owned());
        }
        if self.port == 0 {
            problems.push("RDP port must be between 1 and 65535.".to_owned());
        }
        if let Some(gw) = &self.gateway {
            if gw.host.trim().is_empty() {
                problems.push("Gateway host is required when a gateway is enabled.".to_owned());
            } else if !is_valid_hostname(gw.host.trim()) {
                problems.push("Gateway host contains invalid characters.".to_owned());
            }
            if gw.port == 0 {
                problems.push("Gateway port must be between 1 and 65535.".to_owned());
            }
        }
        if self.drive.enabled {
            if self.drive.local_path.trim().is_empty() {
                problems.push("Choose a local folder to share, or disable drive sharing.".to_owned());
            }
            let name = self.drive.share_name.trim();
            if name.is_empty()
                || name.len() > 31
                || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_'))
            {
                problems.push("Share name must be 1-31 letters, digits, spaces, '-' or '_'.".to_owned());
            }
        }
        problems
    }

    /// `DOMAIN\user` or plain user, as typed into the credential prompt.
    pub fn qualified_username(&self) -> String {
        if self.domain.trim().is_empty() {
            self.username.clone()
        } else {
            format!("{}\\{}", self.domain.trim(), self.username.trim())
        }
    }
}

/// Very conservative host validation: DNS names, IPv4 and bracket-less IPv6.
pub fn is_valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct GatewaySettings {
    pub host: String,
    pub port: u16,
    /// Use the same username/password for the gateway as for the remote PC (mstsc default).
    pub same_credentials: bool,
    pub username: String,
    pub domain: String,
}

impl Default for GatewaySettings {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: DEFAULT_GATEWAY_PORT,
            same_credentials: true,
            username: String::new(),
            domain: String::new(),
        }
    }
}

impl GatewaySettings {
    pub fn endpoint(&self) -> String {
        let host = self.host.trim();
        if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum DisplayMode {
    /// A resizable window; remote resolution follows the window size.
    #[default]
    Window,
    /// Fullscreen on the monitor the window is on.
    Fullscreen,
    /// Fullscreen spanning every monitor (multi-monitor session).
    AllMonitors,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DisplaySettings {
    pub mode: DisplayMode,
    /// Initial window size in logical pixels (used for `Window` mode).
    pub width: u16,
    pub height: u16,
    /// Resize the remote desktop when the local window changes size.
    pub dynamic_resolution: bool,
    /// Pass local HiDPI scale to the remote (e.g. 150 %).
    pub follow_local_scale: bool,
    /// Allow H.264/AVC (GFX) codecs. Falls back to RemoteFX/planar when off.
    pub h264: bool,
    /// Prefer hardware (NVDEC/VAAPI) decode when available.
    pub hardware_decode: bool,
}

impl Default for DisplaySettings {
    fn default() -> Self {
        Self {
            mode: DisplayMode::Window,
            width: 1600,
            height: 900,
            dynamic_resolution: true,
            follow_local_scale: true,
            h264: true,
            hardware_decode: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AudioSettings {
    /// Play remote audio on this computer.
    pub playback: bool,
    /// Send this computer's microphone to the remote session.
    pub microphone: bool,
    /// PulseAudio/PipeWire sink name; `None` = system default (follows default changes).
    pub output_device: Option<String>,
    /// PulseAudio/PipeWire source name; `None` = system default.
    pub input_device: Option<String>,
    /// Target playback buffer in milliseconds (latency vs. robustness on bad networks).
    pub playback_latency_ms: u32,
}

impl Default for AudioSettings {
    fn default() -> Self {
        Self { playback: true, microphone: true, output_device: None, input_device: None, playback_latency_ms: 80 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ClipboardSettings {
    pub enabled: bool,
    /// Allow copying files through the clipboard (both directions).
    pub files: bool,
    /// Maximum bytes per clipboard transfer (text/images/HTML).
    pub max_transfer_mb: u32,
}

impl Default for ClipboardSettings {
    fn default() -> Self {
        Self { enabled: true, files: true, max_transfer_mb: 256 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DriveSettings {
    /// Off by default (user decision): nothing local is exposed unless explicitly enabled.
    pub enabled: bool,
    pub local_path: String,
    /// Name the remote side sees, e.g. "Bastion".
    pub share_name: String,
    pub read_only: bool,
}

impl Default for DriveSettings {
    fn default() -> Self {
        Self { enabled: false, local_path: String::new(), share_name: "Bastion".to_owned(), read_only: false }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct SecuritySettings {
    /// DANGEROUS: skip all certificate validation (lab use only). Shown with a warning in the UI.
    pub allow_insecure_tls: bool,
    /// Remember the password in the OS keyring.
    pub remember_password: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct ReconnectSettings {
    pub enabled: bool,
    pub max_attempts: u32,
}

impl Default for ReconnectSettings {
    fn default() -> Self {
        Self { enabled: true, max_attempts: 20 }
    }
}

/// How long the session must be idle (no input sent) before Bastion moves the remote mouse.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum KeepActive {
    #[default]
    #[serde(rename = "off")]
    Off,
    #[serde(rename = "30s")]
    Secs30,
    #[serde(rename = "1m")]
    Min1,
    #[serde(rename = "5m")]
    Min5,
    #[serde(rename = "10m")]
    Min10,
}

impl KeepActive {
    pub const ALL: [Self; 5] = [Self::Off, Self::Secs30, Self::Min1, Self::Min5, Self::Min10];

    /// `None` = feature disabled.
    pub fn interval(self) -> Option<std::time::Duration> {
        let secs = match self {
            Self::Off => return None,
            Self::Secs30 => 30,
            Self::Min1 => 60,
            Self::Min5 => 5 * 60,
            Self::Min10 => 10 * 60,
        };
        Some(std::time::Duration::from_secs(secs))
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Secs30 => "After 30 seconds idle",
            Self::Min1 => "After 1 minute idle",
            Self::Min5 => "After 5 minutes idle",
            Self::Min10 => "After 10 minutes idle",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_toml() {
        let mut p = Profile { name: "Work".into(), host: "pc01.corp.local".into(), ..Default::default() };
        p.gateway = Some(GatewaySettings { host: "rdg.corp.com".into(), ..Default::default() });
        let s = toml::to_string(&p).unwrap();
        let back: Profile = toml::from_str(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn validation() {
        let p = Profile::default();
        assert!(!p.validate().is_empty());
        let p = Profile { host: "pc 01".into(), ..Default::default() };
        assert!(!p.validate().is_empty());
        let p = Profile { host: "pc01".into(), ..Default::default() };
        assert!(p.validate().is_empty());
    }

    #[test]
    fn keep_active_serializes_and_defaults_off() {
        assert_eq!(Profile::default().keep_active, KeepActive::Off);
        // Profiles saved before the setting existed still load.
        let old: Profile = toml::from_str("host = \"pc01\"").unwrap();
        assert_eq!(old.keep_active, KeepActive::Off);
        let p = Profile { host: "pc01".into(), keep_active: KeepActive::Min5, ..Default::default() };
        let s = toml::to_string(&p).unwrap();
        assert!(s.contains("keep_active = \"5m\""), "{s}");
        assert_eq!(toml::from_str::<Profile>(&s).unwrap().keep_active, KeepActive::Min5);
        assert_eq!(KeepActive::Secs30.interval(), Some(std::time::Duration::from_secs(30)));
        assert_eq!(KeepActive::Off.interval(), None);
    }

    #[test]
    fn gateway_endpoint_ipv6() {
        let g = GatewaySettings { host: "::1".into(), port: 8443, ..Default::default() };
        assert_eq!(g.endpoint(), "[::1]:8443");
    }
}
