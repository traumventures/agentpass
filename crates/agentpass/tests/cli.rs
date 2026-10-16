//! CLI ⇄ daemon integration tests (no browser: the passkey step is replaced by
//! posting a known PRF output to the daemon's HTTP API).

mod common;

use common::Sandbox;

fn code(out: &std::process::Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

#[test]
fn full_cycle_through_the_real_daemon() {
    let mut sb = Sandbox::new();
    sb.start_daemon();

    let out = sb.run(&["set", "DB_PASSWORD", "-d", "postgres"], Some(b"pa55\n"));
    assert!(out.status.success());
    let toml = std::fs::read_to_string(sb.vault()).unwrap();
    assert!(toml.contains("[secrets.DB_PASSWORD]") && !toml.contains("pa55"));

    assert_eq!(code(&sb.run(&["get", "DB_PASSWORD"], None)), 3);
    assert_eq!(code(&sb.run(&["status"], None)), 3);

    sb.unlock(Some(3600));
    let out = sb.run(&["get", "DB_PASSWORD"], None);
    assert_eq!(
        out.stdout,
        b"pa55",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(code(&sb.run(&["wait", "--timeout", "1s"], None)), 0);

    // `set` while unlocked works too, and new values are readable at once.
    assert!(sb.run(&["set", "NEW"], Some(b"v2")).status.success());
    assert_eq!(sb.run(&["get", "NEW"], None).stdout, b"v2");

    // rm, list
    assert!(sb.run(&["rm", "NEW"], None).status.success());
    assert_eq!(code(&sb.run(&["rm", "NEW"], None)), 4);
    let list = sb.run(&["list", "--json"], None);
    let list: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(
        list,
        serde_json::json!([{"key": "DB_PASSWORD", "description": "postgres"}])
    );

    assert!(sb.run(&["lock"], None).status.success());
    assert_eq!(code(&sb.run(&["get", "DB_PASSWORD"], None)), 3);
}

#[test]
fn wrong_prf_is_rejected_and_link_is_single_use() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    let out = sb.run(&["unlock"], None);
    let url = String::from_utf8(out.stdout).unwrap();
    let token = url.trim().split('#').nth(1).unwrap().to_owned();
    let body = |prf: &[u8; 32]| {
        serde_json::json!({
            "kind": "unlocked",
            "credential_id": common::CRED,
            "prf_output": agentpass::crypto::b64url(prf),
            "duration_secs": 60,
        })
        .to_string()
    };
    let (status, _) = sb.http_post("/api/flow/complete", &token, &body(&[0; 32]));
    assert_eq!(status, 400);
    let (status, _) = sb.http_post("/api/flow/complete", &token, &body(&common::PRF));
    assert_eq!(status, 200);
    let (status, _) = sb.http_post("/api/flow/complete", &token, &body(&common::PRF));
    assert_eq!(status, 404, "token must be single-use");
}

#[test]
fn timed_unlock_expires() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    assert!(sb.run(&["set", "K"], Some(b"v")).status.success());
    sb.unlock(Some(1));
    assert_eq!(sb.run(&["get", "K"], None).stdout, b"v");
    std::thread::sleep(std::time::Duration::from_millis(1600));
    assert_eq!(code(&sb.run(&["get", "K"], None)), 3);
}

#[test]
fn large_values_roundtrip_and_oversized_values_are_refused() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    assert!(sb
        .run(&["set", "BIG", "--raw"], Some(&big))
        .status
        .success());
    let too_big = vec![b'x'; agentpass::crypto::MAX_VALUE_LEN + 1];
    assert_eq!(code(&sb.run(&["set", "HUGE"], Some(&too_big))), 2);
    sb.unlock(Some(60));
    assert_eq!(sb.run(&["get", "BIG"], None).stdout, big);
}

#[test]
fn get_refuses_terminals_and_run_validates_names() {
    let sb = Sandbox::new();
    let out = sb.run(&["run", "-e", "1BAD=K", "--", "true"], None);
    assert_eq!(code(&out), 2);
    // No daemon running: everything is locked.
    assert_eq!(code(&sb.run(&["get", "K"], None)), 3);
    assert_eq!(code(&sb.run(&["run", "-e", "K", "--", "true"], None)), 3);
}

#[test]
fn sigterm_locks_and_stops_the_daemon() {
    let mut sb = Sandbox::new();
    let pid = sb.start_daemon();
    sb.unlock(None);
    // SAFETY: plain kill(2).
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    let status = sb.daemon.as_mut().unwrap().wait().unwrap();
    assert!(status.success());
    assert_eq!(code(&sb.run(&["status"], None)), 3);
}
