//! System-tray icon (StatusNotifierItem — KDE Plasma, and GNOME with the AppIndicator extension).
//! Closing the main window keeps Bastion running here; click the icon to reopen it.

use ksni::blocking::TrayMethods as _;
use winit::event_loop::EventLoopProxy;

use crate::app::UserEvent;

pub struct BastionTray {
    proxy: EventLoopProxy<UserEvent>,
    sessions: usize,
}

impl ksni::Tray for BastionTray {
    fn id(&self) -> String {
        "bastion".into()
    }
    fn title(&self) -> String {
        "Bastion".into()
    }
    fn icon_name(&self) -> String {
        "bastion".into()
    }
    fn tool_tip(&self) -> ksni::ToolTip {
        let description = match self.sessions {
            0 => "No active sessions".to_owned(),
            1 => "1 active session".to_owned(),
            n => format!("{n} active sessions"),
        };
        ksni::ToolTip { title: "Bastion Remote Desktop".into(), description, ..Default::default() }
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.proxy.send_event(UserEvent::TrayOpen);
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        vec![
            StandardItem {
                label: "Open Bastion".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.proxy.send_event(UserEvent::TrayOpen);
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Quit (disconnects all sessions)".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|t: &mut Self| {
                    let _ = t.proxy.send_event(UserEvent::TrayQuit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

pub type TrayHandle = ksni::blocking::Handle<BastionTray>;

/// Starts the tray icon; `None` if no tray host is running (then closing the window quits).
pub fn start(proxy: EventLoopProxy<UserEvent>) -> Option<TrayHandle> {
    match (BastionTray { proxy, sessions: 0 }).spawn() {
        Ok(h) => Some(h),
        Err(e) => {
            tracing::info!(error = %e, "System tray unavailable; closing the window will quit");
            None
        }
    }
}

pub fn set_sessions(handle: &TrayHandle, n: usize) {
    handle.update(|t| t.sessions = n);
}
