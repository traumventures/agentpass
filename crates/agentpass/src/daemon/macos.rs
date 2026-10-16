//! macOS: lock every vault before the system sleeps, using IOKit's
//! `IORegisterForSystemPower` on a dedicated CFRunLoop thread.

use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use super::{log, Daemon};

type IoConnect = u32;
type IoObject = u32;
type IoService = u32;
type NotificationPort = *mut c_void;
type RunLoopSource = *mut c_void;
type RunLoop = *mut c_void;
type CFString = *const c_void;

const MSG_CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;
const MSG_SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        port: *mut NotificationPort,
        callback: extern "C" fn(*mut c_void, IoService, u32, *mut c_void),
        notifier: *mut IoObject,
    ) -> IoConnect;
    fn IONotificationPortGetRunLoopSource(port: NotificationPort) -> RunLoopSource;
    fn IOAllowPowerChange(kernel_port: IoConnect, notification_id: isize) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFRunLoopDefaultMode: CFString;
    fn CFRunLoopGetCurrent() -> RunLoop;
    fn CFRunLoopAddSource(rl: RunLoop, source: RunLoopSource, mode: CFString);
    fn CFRunLoopRun();
}

static DAEMON: OnceLock<Arc<Daemon>> = OnceLock::new();
static ROOT_PORT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_power(_refcon: *mut c_void, _service: IoService, msg: u32, arg: *mut c_void) {
    match msg {
        MSG_SYSTEM_WILL_SLEEP => {
            if let Some(d) = DAEMON.get() {
                d.lock_all("system is going to sleep");
            }
            // SAFETY: acknowledging the notification we were sent.
            unsafe { IOAllowPowerChange(ROOT_PORT.load(Ordering::SeqCst), arg as isize) };
        }
        MSG_CAN_SYSTEM_SLEEP => {
            // SAFETY: as above.
            unsafe { IOAllowPowerChange(ROOT_PORT.load(Ordering::SeqCst), arg as isize) };
        }
        _ => {}
    }
}

pub fn spawn_power_watch(d: Arc<Daemon>) {
    if DAEMON.set(d).is_err() {
        return;
    }
    std::thread::Builder::new()
        .name("power-watch".into())
        .spawn(|| {
            let mut port: NotificationPort = std::ptr::null_mut();
            let mut notifier: IoObject = 0;
            // SAFETY: out-pointers are valid; the callback has the C ABI.
            unsafe {
                let root = IORegisterForSystemPower(
                    std::ptr::null_mut(),
                    &mut port,
                    on_power,
                    &mut notifier,
                );
                if root == 0 || port.is_null() {
                    log!("could not register for macOS sleep notifications; relying on the sleep clock watcher");
                    return;
                }
                ROOT_PORT.store(root, Ordering::SeqCst);
                CFRunLoopAddSource(
                    CFRunLoopGetCurrent(),
                    IONotificationPortGetRunLoopSource(port),
                    kCFRunLoopDefaultMode,
                );
                log!("watching macOS power notifications for sleep");
                CFRunLoopRun();
            }
        })
        .ok();
}
