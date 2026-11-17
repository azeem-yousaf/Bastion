//! Wayland keyboard-shortcuts-inhibit: lets Alt+Tab, Super, Alt+F4 … reach the remote session
//! while it has keyboard focus (like a native Windows client). The compositor (KWin) asks the
//! user for permission the first time. Ctrl+Alt+Home always releases it.

use wayland_backend::client::{Backend, ObjectId};
use wayland_client::protocol::{wl_registry, wl_seat, wl_surface};
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle};
use wayland_protocols::wp::keyboard_shortcuts_inhibit::zv1::client::{
    zwp_keyboard_shortcuts_inhibit_manager_v1 as mgr, zwp_keyboard_shortcuts_inhibitor_v1 as inh,
};
use winit::raw_window_handle::{HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle};
use winit::window::Window;

#[derive(Default)]
struct State {
    manager: Option<mgr::ZwpKeyboardShortcutsInhibitManagerV1>,
    seat: Option<wl_seat::WlSeat>,
    active: bool,
}

impl Dispatch<wl_registry::WlRegistry, ()> for State {
    fn event(
        state: &mut Self,
        registry: &wl_registry::WlRegistry,
        event: wl_registry::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_registry::Event::Global { name, interface, .. } = event {
            match interface.as_str() {
                "zwp_keyboard_shortcuts_inhibit_manager_v1" => state.manager = Some(registry.bind(name, 1, qh, ())),
                "wl_seat" if state.seat.is_none() => state.seat = Some(registry.bind(name, 1, qh, ())),
                _ => {}
            }
        }
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for State {
    fn event(_: &mut Self, _: &wl_seat::WlSeat, _: wl_seat::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {}
}

impl Dispatch<mgr::ZwpKeyboardShortcutsInhibitManagerV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &mgr::ZwpKeyboardShortcutsInhibitManagerV1,
        _: mgr::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<inh::ZwpKeyboardShortcutsInhibitorV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &inh::ZwpKeyboardShortcutsInhibitorV1,
        event: inh::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        state.active = matches!(event, inh::Event::Active);
        tracing::debug!(active = state.active, "Shortcut inhibitor state");
    }
}

/// Per-window inhibitor. Must be dropped before the window it was created for.
pub struct ShortcutInhibitor {
    _conn: Connection,
    queue: EventQueue<State>,
    state: State,
    surface: wl_surface::WlSurface,
    inhibitor: Option<inh::ZwpKeyboardShortcutsInhibitorV1>,
}

impl ShortcutInhibitor {
    /// Returns `None` on X11 or when the compositor lacks the protocol.
    pub fn new(window: &Window) -> Option<Self> {
        let RawDisplayHandle::Wayland(d) = window.display_handle().ok()?.as_raw() else { return None };
        let RawWindowHandle::Wayland(w) = window.window_handle().ok()?.as_raw() else { return None };
        // SAFETY: winit keeps the display alive for the lifetime of the event loop, which outlives
        // every window and therefore this inhibitor; the surface pointer is valid while the window
        // exists, and the owner drops the inhibitor before the window.
        let backend = unsafe { Backend::from_foreign_display(d.display.as_ptr().cast()) };
        let conn = Connection::from_backend(backend);
        let mut queue = conn.new_event_queue();
        let qh = queue.handle();
        let _registry = conn.display().get_registry(&qh, ());
        let mut state = State::default();
        queue.roundtrip(&mut state).ok()?;
        if state.manager.is_none() || state.seat.is_none() {
            tracing::info!("Compositor does not support keyboard-shortcuts-inhibit");
            return None;
        }
        let id = unsafe { ObjectId::from_ptr(wl_surface::WlSurface::interface(), w.surface.as_ptr().cast()) }.ok()?;
        let surface = wl_surface::WlSurface::from_id(&conn, id).ok()?;
        Some(Self { _conn: conn, queue, state, surface, inhibitor: None })
    }

    /// Enables or disables forwarding of system shortcuts to this window.
    pub fn set(&mut self, enabled: bool) {
        match (enabled, self.inhibitor.is_some()) {
            (true, false) => {
                let (Some(m), Some(seat)) = (&self.state.manager, &self.state.seat) else { return };
                self.inhibitor = Some(m.inhibit_shortcuts(&self.surface, seat, &self.queue.handle(), ()));
            }
            (false, true) => {
                if let Some(i) = self.inhibitor.take() {
                    i.destroy();
                }
            }
            _ => return,
        }
        let _ = self.queue.flush();
        let _ = self.queue.dispatch_pending(&mut self.state);
    }
}

impl Drop for ShortcutInhibitor {
    fn drop(&mut self) {
        self.set(false);
        if let Some(m) = self.state.manager.take() {
            m.destroy();
        }
        let _ = self.queue.flush();
    }
}
