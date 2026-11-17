//! Bastion session engine: connects (directly or through an RD Gateway), drives the RDP
//! session, and exposes a thread-safe handle for the UI.

pub mod drive;
pub mod engine;
pub mod frame;
mod gfx;
mod keep_active;
pub mod keyboard;
pub mod layout;
pub mod tls;

pub use engine::{Command, ConnectParams, Event, PointerEvent, SessionHandle, Status, Waker};
pub use frame::{Rect, SharedFrame};
pub use layout::{DesktopLayout, LocalMonitor, MonitorSpec, pack_monitors};
