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

    sb.put("DB_PASSWORD", b"pa55", Some("postgres"));
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

    // Secrets added while unlocked are readable at once.
    sb.put("NEW", b"v2", None);
    assert_eq!(sb.run(&["get", "NEW"], None).stdout, b"v2");
    let mut v = agentpass::vault::Vault::load(&sb.vault()).unwrap();
    v.file.secrets.remove("NEW");
    v.save().unwrap();
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
    let body = |prf: &[u8; 32]| {
        serde_json::json!({
            "kind": "unlocked",
            "credential_id": common::CRED,
            "prf_output": agentpass::crypto::b64url(prf),
            "duration_secs": 60,
        })
        .to_string()
    };
    let (status, _) = common::http_complete(&url, &body(&[0; 32]));
    assert_eq!(status, 400);
    let (status, _) = common::http_complete(&url, &body(&common::PRF));
    assert_eq!(status, 200);
    let (status, _) = common::http_complete(&url, &body(&common::PRF));
    assert_eq!(status, 404, "token must be single-use");
}

#[test]
fn timed_unlock_expires() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    sb.put("K", b"v", None);
    sb.unlock(Some(1));
    assert_eq!(sb.run(&["get", "K"], None).stdout, b"v");
    std::thread::sleep(std::time::Duration::from_millis(1600));
    assert_eq!(code(&sb.run(&["get", "K"], None)), 3);
}

#[test]
fn large_values_roundtrip() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    sb.put("BIG", &big, None);
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

#[test]
fn several_vaults_require_file() {
    let sb = Sandbox::new();
    std::fs::copy(sb.vault(), sb.dir.path().join("prod.agentpass.toml")).unwrap();
    let out = sb
        .cmd(&["list"])
        .env_remove("AGENTPASS_FILE")
        .output()
        .unwrap();
    assert_eq!(code(&out), 2);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("prod.agentpass.toml") && stderr.contains("secrets.agentpass.toml"),
        "{stderr}"
    );
    assert!(stderr.contains("--file"), "{stderr}");
    let out = sb
        .cmd(&["--file", "./prod.agentpass.toml", "list"])
        .env_remove("AGENTPASS_FILE")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn folder_secrets_work_with_get_and_run() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    sb.put("production/DB_PASSWORD", b"prod-pw", None);
    sb.put("testing/DB_PASSWORD", b"test-pw", None);
    assert_eq!(code(&sb.run(&["request", "bad//name"], None)), 2);
    sb.unlock(Some(60));
    assert_eq!(
        sb.run(&["get", "testing/DB_PASSWORD"], None).stdout,
        b"test-pw"
    );
    let out = sb.run(
        &[
            "run",
            "-e",
            "production/DB_PASSWORD",
            "--",
            "sh",
            "-c",
            "printf %s \"$DB_PASSWORD\"",
        ],
        None,
    );
    assert_eq!(
        out.stdout,
        b"prod-pw",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn vault_name_can_be_shown_and_changed() {
    let sb = Sandbox::new();
    assert_eq!(sb.run(&["name"], None).stdout, b"test\n");
    assert!(sb.run(&["name", "Production keys"], None).status.success());
    assert_eq!(sb.run(&["name"], None).stdout, b"Production keys\n");
    let toml = std::fs::read_to_string(sb.vault()).unwrap();
    assert!(toml.contains("name = \"Production keys\""));
    assert_eq!(code(&sb.run(&["name", ""], None)), 2);
}

#[test]
fn vault_is_found_by_suffix_from_subdirectories() {
    let sb = Sandbox::new();
    let sub = sb.dir.path().join("src/deep");
    std::fs::create_dir_all(&sub).unwrap();
    let out = sb
        .cmd(&["list", "--json"])
        .env_remove("AGENTPASS_FILE")
        .current_dir(&sub)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // A second vault, selected by name.
    std::fs::copy(sb.vault(), sb.dir.path().join("prod.agentpass.toml")).unwrap();
    let out = sb
        .cmd(&["--file", "prod", "name"])
        .env_remove("AGENTPASS_FILE")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn setup_names_the_vault_after_its_directory_by_default() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    let project = sb.dir.path().join("my-project");
    std::fs::create_dir(&project).unwrap();
    let out = sb
        .cmd(&["setup", "--timeout", "1s"])
        .env_remove("AGENTPASS_FILE")
        .current_dir(&project)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Creating vault \"my-project\""), "{stderr}");
    assert!(stderr.contains("secrets.agentpass.toml"), "{stderr}");
    assert_eq!(code(&out), 5, "times out without a browser");
}

#[test]
fn skill_is_printed_and_installed() {
    let sb = Sandbox::new();
    let out = sb.run(&["skill"], None);
    let skill = String::from_utf8(out.stdout).unwrap();
    assert!(skill.starts_with("---\nname: agentpass\n"));

    let home = sb.dir.path().join("home");
    let project = sb.dir.path().join("proj");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    let run = |args: &[&str]| {
        sb.cmd(args)
            .env("HOME", &home)
            .current_dir(&project)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    let out = run(&[
        "init-skill",
        "--tool",
        "claude",
        "--tool",
        "copilot",
        "--project",
        "--yes",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for p in [
        ".claude/skills/agentpass/SKILL.md",
        ".github/skills/agentpass/SKILL.md",
    ] {
        assert_eq!(std::fs::read_to_string(project.join(p)).unwrap(), skill);
    }
    let out = run(&["init-skill", "--all", "--global", "--yes"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for p in [
        ".claude/skills",
        ".agents/skills",
        ".cursor/skills",
        ".copilot/skills",
        ".gemini/skills",
        ".config/opencode/skills",
    ] {
        assert!(home.join(p).join("agentpass/SKILL.md").is_file(), "{p}");
    }
    // Without a terminal and without flags it explains what to pass.
    let out = run(&["init-skill"]);
    assert_eq!(code(&out), 1);
    assert!(String::from_utf8_lossy(&out.stderr).contains("--tool"));
}

#[test]
fn there_is_no_cli_command_to_write_secrets() {
    let sb = Sandbox::new();
    for cmd in ["set", "rm", "add", "put"] {
        let out = sb.run(&[cmd, "K"], Some(b"v"));
        assert_eq!(code(&out), 2, "`{cmd}` must not exist");
    }
}

/// Starts a browser flow command and returns (child, link).
fn start_flow(sb: &Sandbox, args: &[&str]) -> (std::process::Child, String) {
    use std::io::BufRead;
    let mut child = sb
        .cmd(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    std::io::BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert!(line.starts_with("http://localhost:"), "{line}");
    (child, line.trim().to_owned())
}

#[test]
fn request_lets_the_user_rename_and_reports_the_final_name() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    let (child, url) = start_flow(
        &sb,
        &[
            "request",
            "STRIPE_KEY",
            "-d",
            "Stripe",
            "--reason",
            "deploy",
            "--timeout",
            "30s",
        ],
    );
    let body = serde_json::json!({
        "kind": "provided",
        "key": "production/STRIPE_SECRET",
        "description": "live key",
        "value": "sk_live_123",
    });
    let (status, resp) = common::http_complete(&url, &body.to_string());
    assert_eq!(status, 200, "{resp}");
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"production/STRIPE_SECRET\n");
    let toml = std::fs::read_to_string(sb.vault()).unwrap();
    assert!(toml.contains("description = \"live key\"") && !toml.contains("sk_live_123"));
    sb.unlock(Some(60));
    assert_eq!(
        sb.run(&["get", "production/STRIPE_SECRET"], None).stdout,
        b"sk_live_123"
    );
}

#[test]
fn request_refuses_silent_overwrite_and_can_be_declined() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    sb.put("K", b"old", None);
    let (child, url) = start_flow(&sb, &["request", "K", "--timeout", "30s"]);
    let body = |replace: bool| {
        serde_json::json!({ "kind": "provided", "key": "K", "value": "new", "replace": replace })
            .to_string()
    };
    assert_eq!(common::http_complete(&url, &body(false)).0, 400);
    let (status, _) = common::http_complete(&url, r#"{"kind":"declined"}"#);
    assert_eq!(status, 200);
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 1);
    assert!(String::from_utf8_lossy(&out.stderr).contains("declined"));
    assert!(out.stdout.is_empty());
}

#[test]
fn editor_needs_the_passkey_then_applies_changes_atomically() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    sb.put("prod/A", b"a", Some("first"));
    sb.put("B", b"b", None);
    let (child, url) = start_flow(&sb, &["edit", "--timeout", "30s"]);
    let ops = |ops: serde_json::Value| serde_json::json!({ "ops": ops }).to_string();
    let rename = ops(serde_json::json!([
        { "op": "rename", "from": "prod/A", "to": "production/A" },
        { "op": "delete", "key": "B" },
        { "op": "put", "key": "production/C", "value": "c", "description": "new" },
    ]));
    // Before the passkey check nothing can be changed.
    assert_eq!(common::http_post(&url, "/api/edit", &rename).0, 400);
    let auth = serde_json::json!({
        "kind": "edit_auth",
        "credential_id": common::CRED,
        "prf_output": agentpass::crypto::b64url(&common::PRF),
    });
    assert_eq!(common::http_complete(&url, &auth.to_string()).0, 200);
    // Opening the editor does not unlock the vault for agents.
    assert_eq!(code(&sb.run(&["get", "B"], None)), 3);
    // A failing batch changes nothing.
    let bad = ops(serde_json::json!([
        { "op": "delete", "key": "B" },
        { "op": "delete", "key": "NOPE" },
    ]));
    assert_eq!(common::http_post(&url, "/api/edit", &bad).0, 400);
    let (status, resp) = common::http_post(&url, "/api/edit", &rename);
    assert_eq!(status, 200, "{resp}");
    assert_eq!(
        common::http_complete(&url, r#"{"kind":"edit_closed"}"#).0,
        200
    );
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    sb.unlock(Some(60));
    assert_eq!(sb.run(&["get", "production/A"], None).stdout, b"a");
    assert_eq!(sb.run(&["get", "production/C"], None).stdout, b"c");
    assert_eq!(code(&sb.run(&["get", "B"], None)), 4);
    let v = agentpass::vault::Vault::load(&sb.vault()).unwrap();
    assert_eq!(
        v.file.secrets["production/A"].description.as_deref(),
        Some("first")
    );
}

#[test]
fn no_wait_then_wait_flow_reports_the_result() {
    let mut sb = Sandbox::new();
    sb.start_daemon();
    let out = sb.run(&["request", "API_KEY", "--no-wait"], None);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let url = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let flow = stderr
        .lines()
        .find_map(|l| l.strip_prefix("flow: "))
        .expect("flow id printed")
        .to_owned();
    // Not done yet: a short wait times out.
    assert_eq!(
        code(&sb.run(&["wait", "--flow", &flow, "--timeout", "1s"], None)),
        5
    );
    let body = serde_json::json!({ "kind": "provided", "key": "prod/API_KEY", "value": "v" });
    assert_eq!(common::http_complete(&url, &body.to_string()).0, 200);
    let out = sb.run(&["wait", "--flow", &flow], None);
    assert!(out.status.success());
    assert_eq!(out.stdout, b"prod/API_KEY\n");
}
