//! Enumerates PulseAudio/PipeWire sinks (speakers/headphones) and sources (microphones).

use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};
use libpulse_binding::callbacks::ListResult;
use libpulse_binding::context::{Context, FlagSet, State};
use libpulse_binding::mainloop::standard::{IterateResult, Mainloop};
use libpulse_binding::operation::{Operation, State as OpState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioDevice {
    /// Stable identifier passed back to the audio host (Pulse sink/source name).
    pub name: String,
    /// Human-readable, e.g. "SteelSeries Arctis 7 Chat".
    pub description: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceList {
    pub outputs: Vec<AudioDevice>,
    pub inputs: Vec<AudioDevice>,
}

const TIMEOUT: Duration = Duration::from_secs(3);

fn iterate(ml: &mut Mainloop, deadline: Instant) -> Result<()> {
    if Instant::now() > deadline {
        bail!("timed out talking to the sound server");
    }
    match ml.iterate(false) {
        IterateResult::Success(0) => std::thread::sleep(Duration::from_millis(2)),
        IterateResult::Success(_) => {}
        IterateResult::Quit(_) | IterateResult::Err(_) => bail!("sound server main loop failed"),
    }
    Ok(())
}

fn wait<T: ?Sized>(ml: &mut Mainloop, op: &Operation<T>, deadline: Instant) -> Result<()> {
    while op.get_state() == OpState::Running {
        iterate(ml, deadline)?;
    }
    Ok(())
}

/// Lists devices. Monitor sources (loopbacks of outputs) are excluded from inputs.
pub fn list_devices() -> Result<DeviceList> {
    let deadline = Instant::now() + TIMEOUT;
    let mut ml = Mainloop::new().ok_or_else(|| anyhow!("cannot create pulse main loop"))?;
    let mut ctx = Context::new(&ml, crate::host::APP_NAME).ok_or_else(|| anyhow!("cannot create pulse context"))?;
    ctx.connect(None, FlagSet::NOAUTOSPAWN, None).map_err(|e| anyhow!("connect to sound server: {e}"))?;
    loop {
        match ctx.get_state() {
            State::Ready => break,
            State::Failed | State::Terminated => bail!("sound server connection failed"),
            _ => iterate(&mut ml, deadline)?,
        }
    }

    let defaults: Rc<RefCell<(String, String)>> = Rc::default();
    let out: Rc<RefCell<DeviceList>> = Rc::default();
    let intro = ctx.introspect();

    {
        let d = defaults.clone();
        let op = intro.get_server_info(move |info| {
            *d.borrow_mut() = (
                info.default_sink_name.as_deref().unwrap_or_default().to_owned(),
                info.default_source_name.as_deref().unwrap_or_default().to_owned(),
            );
        });
        wait(&mut ml, &op, deadline)?;
    }
    {
        let o = out.clone();
        let op = intro.get_sink_info_list(move |r| {
            if let ListResult::Item(s) = r {
                o.borrow_mut().outputs.push(AudioDevice {
                    name: s.name.as_deref().unwrap_or_default().to_owned(),
                    description: s.description.as_deref().unwrap_or_default().to_owned(),
                    is_default: false,
                });
            }
        });
        wait(&mut ml, &op, deadline)?;
    }
    {
        let o = out.clone();
        let op = intro.get_source_info_list(move |r| {
            if let ListResult::Item(s) = r
                && s.monitor_of_sink.is_none()
            {
                o.borrow_mut().inputs.push(AudioDevice {
                    name: s.name.as_deref().unwrap_or_default().to_owned(),
                    description: s.description.as_deref().unwrap_or_default().to_owned(),
                    is_default: false,
                });
            }
        });
        wait(&mut ml, &op, deadline)?;
    }
    ctx.disconnect();

    let (def_sink, def_source) = defaults.borrow().clone();
    let mut list = out.borrow().clone();
    for d in &mut list.outputs {
        d.is_default = d.name == def_sink;
    }
    for d in &mut list.inputs {
        d.is_default = d.name == def_source;
    }
    Ok(list)
}
