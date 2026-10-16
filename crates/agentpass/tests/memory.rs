//! Memory-protection tests against a real daemon process.
//!
//! The tests marked `#[ignore]` need root (they read the daemon's memory via
//! `sudo -n`): `cargo test -p agentpass --test memory -- --ignored`.

#![cfg(target_os = "linux")]

mod common;

use std::process::Command;

use common::Sandbox;

#[test]
fn same_user_cannot_read_daemon_memory_or_ptrace_it() {
    let mut sb = Sandbox::new();
    let pid = sb.start_daemon();
    sb.unlock(None);

    let err = std::fs::File::open(format!("/proc/{pid}/mem")).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    assert!(std::fs::read(format!("/proc/{pid}/environ")).is_err());

    // SAFETY: PTRACE_ATTACH on another process; we detach if it succeeds.
    let rc = unsafe { libc::ptrace(libc::PTRACE_ATTACH, pid as libc::pid_t, 0, 0) };
    let errno = std::io::Error::last_os_error();
    if rc == 0 {
        unsafe { libc::ptrace(libc::PTRACE_DETACH, pid as libc::pid_t, 0, 0) };
        panic!("ptrace attach to the daemon succeeded");
    }
    assert_eq!(errno.raw_os_error(), Some(libc::EPERM));
}

#[test]
fn core_dumps_are_disabled() {
    let mut sb = Sandbox::new();
    let pid = sb.start_daemon();
    let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|l| l.starts_with("Max core file size"))
        .unwrap();
    let fields: Vec<&str> = core.split_whitespace().collect();
    assert_eq!(&fields[4..6], &["0", "0"], "{core}");

    sb.unlock(None);
    // Crash it: no core file may appear in its working directory.
    unsafe { libc::kill(pid as i32, libc::SIGABRT) };
    let status = sb.daemon.as_mut().unwrap().wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(libc::SIGABRT));
    assert!(!status.core_dumped(), "kernel reported a core dump");
    let cores: Vec<_> = std::fs::read_dir(sb.dir.path())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("core"))
        .collect();
    assert!(cores.is_empty(), "core file written: {cores:?}");
}

fn sudo_available() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Uses root to scan every readable mapping of `pid` for `needle`. Returns
/// the matching mappings' smaps VmFlags.
fn scan(pid: u32, needle: &[u8]) -> Vec<String> {
    let script = r#"
import sys, re
pid, needle = int(sys.argv[1]), bytes.fromhex(sys.argv[2])
flags, cur, out = {}, None, []
for line in open(f"/proc/{pid}/smaps"):
    m = re.match(r"^([0-9a-f]+)-([0-9a-f]+) (\S+)", line)
    if m:
        cur = (int(m.group(1), 16), int(m.group(2), 16), m.group(3))
    elif line.startswith("VmFlags:") and cur:
        flags[cur] = line.split(":", 1)[1].strip()
mem = open(f"/proc/{pid}/mem", "rb", 0)
for (start, end, perms), fl in flags.items():
    if not perms.startswith("r"):
        continue
    try:
        mem.seek(start)
        data = mem.read(end - start)
    except OSError:
        continue
    if needle in data:
        out.append(fl)
print("\n".join(out))
"#;
    let out = Command::new("sudo")
        .args([
            "-n",
            "python3",
            "-c",
            script,
            &pid.to_string(),
            &hex(needle),
        ])
        .output()
        .expect("running sudo python3");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
#[ignore = "needs passwordless sudo to read the daemon's memory"]
fn key_lives_only_in_locked_nodump_memory_and_is_wiped_on_lock() {
    assert!(sudo_available(), "needs `sudo -n`");
    let mut sb = Sandbox::new();
    let pid = sb.start_daemon();
    let secret = b"plaintext-canary-7f3a9c1e5b2d4086";
    sb.put("CANARY", secret, None);

    assert!(scan(pid, &sb.key).is_empty(), "key in memory before unlock");
    sb.unlock(None);

    let hits = scan(pid, &sb.key);
    assert_eq!(
        hits.len(),
        1,
        "expected the key in exactly one mapping, got {hits:?}"
    );
    let flags = &hits[0];
    assert!(
        flags.split(' ').any(|f| f == "lo"),
        "key mapping not mlocked: {flags}"
    );
    assert!(
        flags.split(' ').any(|f| f == "dd"),
        "key mapping not MADV_DONTDUMP: {flags}"
    );

    // Serving a secret must not leave its plaintext behind in the daemon.
    let out = sb.run(&["get", "CANARY"], None);
    assert_eq!(out.stdout, secret);
    assert!(scan(pid, secret).is_empty(), "plaintext lingers after get");

    assert!(sb.run(&["lock"], None).status.success());
    assert!(scan(pid, &sb.key).is_empty(), "key bytes remain after lock");
}
