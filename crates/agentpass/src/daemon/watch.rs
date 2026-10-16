//! Locks every vault when the machine sleeps or the user's session ends.
//!
//! * Linux: logind's `PrepareForSleep` signal locks *before* suspend or
//!   hibernation; `SessionRemoved` for the daemon's session locks and exits.
//! * macOS: IOKit system power notifications lock before sleep (see
//!   `macos.rs`).
//! * Everywhere: a clock watcher compares a clock that runs during sleep with
//!   one that does not, and locks after any resume that slipped through.

use std::sync::Arc;
use std::time::Duration;

#[cfg(target_os = "linux")]
use super::log;
use super::Daemon;

pub fn spawn(d: Arc<Daemon>) {
    tokio::spawn(clock_watch(d.clone()));
    #[cfg(target_os = "linux")]
    tokio::spawn(async move {
        if let Err(e) = logind::watch(d).await {
            log!("logind integration unavailable ({e}); relying on the sleep clock watcher");
        }
    });
    #[cfg(target_os = "macos")]
    super::macos::spawn_power_watch(d);
}

fn clock_secs(id: libc::clockid_t) -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid timespec pointer.
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

/// (clock including sleep, clock excluding sleep)
fn clocks() -> (f64, f64) {
    #[cfg(target_os = "linux")]
    {
        (
            clock_secs(libc::CLOCK_BOOTTIME),
            clock_secs(libc::CLOCK_MONOTONIC),
        )
    }
    #[cfg(target_os = "macos")]
    {
        (
            clock_secs(libc::CLOCK_MONOTONIC),
            clock_secs(libc::CLOCK_UPTIME_RAW),
        )
    }
}

/// Seconds of suspended time that count as "the machine slept".
const SLEEP_THRESHOLD: f64 = 5.0;

async fn clock_watch(d: Arc<Daemon>) {
    let (mut with_sleep, mut without_sleep) = clocks();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let (a, b) = clocks();
        let slept = (a - with_sleep) - (b - without_sleep);
        if slept > SLEEP_THRESHOLD {
            d.lock_all(&format!("system was suspended for {slept:.0}s"));
        }
        (with_sleep, without_sleep) = (a, b);
    }
}

#[cfg(target_os = "linux")]
mod logind {
    use super::*;
    use futures_util::StreamExt;

    pub async fn watch(d: Arc<Daemon>) -> zbus::Result<()> {
        let conn = zbus::Connection::system().await?;
        let manager = zbus::Proxy::new(
            &conn,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        let mut sleep = manager.receive_signal("PrepareForSleep").await?;
        let mut removed = manager.receive_signal("SessionRemoved").await?;
        let session = std::env::var("XDG_SESSION_ID").ok();
        log!(
            "watching logind for sleep{}",
            session
                .as_deref()
                .map(|s| format!(" and end of session {s}"))
                .unwrap_or_default()
        );
        loop {
            tokio::select! {
                Some(msg) = sleep.next() => {
                    if let Ok(true) = msg.body().deserialize::<bool>() {
                        d.lock_all("system is going to sleep");
                    }
                }
                Some(msg) = removed.next() => {
                    if let Ok((id, _path)) = msg.body().deserialize::<(String, zbus::zvariant::OwnedObjectPath)>() {
                        if session.as_deref() == Some(id.as_str()) {
                            d.lock_all("user session ended");
                            d.shutdown.notify_one();
                        }
                    }
                }
                else => return Ok(()),
            }
        }
    }
}
