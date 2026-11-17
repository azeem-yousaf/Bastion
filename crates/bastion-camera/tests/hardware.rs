//! Real-camera smoke test. Needs a webcam, so it's ignored by default:
//!   cargo test -p bastion-camera --test hardware -- --ignored --nocapture

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bastion_camera::{CameraHost as _, V4l2Host, advertised_modes};

#[test]
#[ignore = "needs a real webcam"]
fn captures_frames_from_first_camera() {
    let host = V4l2Host;
    let cams = host.cameras();
    for c in &cams {
        println!("{} ({}): offering {:?}", c.name, c.id, advertised_modes(&c.modes));
    }
    let cam = cams.first().expect("no camera found");
    let mode = advertised_modes(&cam.modes)[0];
    let frames = Arc::new(Mutex::new(Vec::<usize>::new()));
    let f = frames.clone();
    let capture = host.start(cam, mode, Box::new(move |b: &[u8]| f.lock().unwrap().push(b.len()))).unwrap();
    let start = Instant::now();
    while frames.lock().unwrap().len() < 10 {
        assert!(start.elapsed() < Duration::from_secs(10), "no frames from camera");
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(capture);
    let sizes = frames.lock().unwrap().clone();
    println!("{mode:?}: got {} frames in {:?}, sizes {:?}", sizes.len(), start.elapsed(), &sizes[..5]);
}
