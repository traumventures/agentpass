use super::*;
use agentpass_protocol::FlowCompletion;

fn daemon() -> Daemon {
    Daemon {
        state: Mutex::new(State::default()),
        port: 1,
        last_activity: Mutex::new(Instant::now()),
        shutdown: tokio::sync::Notify::new(),
    }
}

fn token_of(resp: &Response) -> (String, String) {
    let Response::FlowStarted { flow_id, url } = resp else {
        panic!("expected flow")
    };
    (flow_id.clone(), url.split('#').nth(1).unwrap().to_owned())
}

const CRED: &str = "Y3JlZGVudGlhbC0x";

fn setup_vault(d: &Daemon, dir: &Path, prf: &[u8; 32]) -> PathBuf {
    let path = dir.join("secrets.agentpass.toml");
    let (resp, _) = d
        .handle(Request::Setup {
            vault_path: path.clone(),
            name: Some("demo".into()),
            label: None,
        })
        .unwrap();
    let (flow_id, token) = token_of(&resp);
    let info = d.flow_info(&token).unwrap();
    assert!(matches!(info, proto::FlowInfo::Setup(ref r) if r.vault.name == "demo"));
    d.complete_flow(
        &token,
        FlowCompletion::Registered {
            credential_id: CRED.into(),
            prf_output: crypto::b64url(prf),
            label: "YubiKey".into(),
        },
    )
    .unwrap();
    let (resp, _) = d.handle(Request::FlowStatus { flow_id }).unwrap();
    assert!(matches!(
        resp,
        Response::FlowState {
            state: FlowState::Done { .. }
        }
    ));
    assert!(d.flow_info(&token).is_err(), "token is single-use");
    path
}

fn unlock(d: &Daemon, path: &Path, prf: &[u8; 32], secs: Option<u64>) -> Result<String, Fail> {
    let (resp, _) = d
        .handle(Request::Unlock {
            vault_path: path.to_owned(),
            suggest_secs: Some(3600),
        })
        .unwrap();
    let (_, token) = token_of(&resp);
    d.complete_flow(
        &token,
        FlowCompletion::Unlocked {
            credential_id: CRED.into(),
            prf_output: crypto::b64url(prf),
            duration_secs: secs,
        },
    )
}

fn get(d: &Daemon, path: &Path, key: &str) -> Result<Vec<u8>, Fail> {
    d.handle(Request::Get {
        vault_path: path.to_owned(),
        key: key.into(),
    })
    .map(|(_, s)| s.unwrap().as_slice().to_vec())
}

#[test]
fn setup_set_unlock_get_lock() {
    let dir = tempfile::tempdir().unwrap();
    let d = daemon();
    let prf = [42u8; 32];
    let path = setup_vault(&d, dir.path(), &prf);

    let mut v = Vault::load(&path).unwrap();
    assert_eq!(v.file.passkeys[0].label, "YubiKey");
    v.set_secret("TOKEN", b"s3cr3t", Some("demo".into()))
        .unwrap();
    v.save().unwrap();

    let e = get(&d, &path, "TOKEN").unwrap_err();
    assert_eq!(e.code, ErrorCode::Locked);

    let e = unlock(&d, &path, &[1u8; 32], Some(60)).unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);

    unlock(&d, &path, &prf, None).unwrap();
    assert_eq!(get(&d, &path, "TOKEN").unwrap(), b"s3cr3t");
    assert_eq!(
        get(&d, &path, "NOPE").unwrap_err().code,
        ErrorCode::NotFound
    );
    assert_eq!(d.statuses()[0].expires_in_secs, None);

    let (resp, _) = d
        .handle(Request::Lock {
            vault_path: Some(path.clone()),
        })
        .unwrap();
    assert!(matches!(resp, Response::Locked { count: 1 }));
    assert_eq!(get(&d, &path, "TOKEN").unwrap_err().code, ErrorCode::Locked);
}

#[test]
fn duration_expires_and_bounds_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let d = daemon();
    let prf = [7u8; 32];
    let path = setup_vault(&d, dir.path(), &prf);
    assert_eq!(
        unlock(&d, &path, &prf, Some(0)).unwrap_err().code,
        ErrorCode::Invalid
    );
    assert_eq!(
        unlock(&d, &path, &prf, Some(MAX_DURATION.as_secs() + 1))
            .unwrap_err()
            .code,
        ErrorCode::Invalid
    );
    unlock(&d, &path, &prf, Some(1)).unwrap();
    assert_eq!(d.statuses().len(), 1);
    std::thread::sleep(Duration::from_millis(1100));
    d.reap();
    assert!(d.statuses().is_empty());
}

#[test]
fn too_many_failed_attempts_burn_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let d = daemon();
    let prf = [3u8; 32];
    let path = setup_vault(&d, dir.path(), &prf);
    let (resp, _) = d
        .handle(Request::Unlock {
            vault_path: path.clone(),
            suggest_secs: None,
        })
        .unwrap();
    let (flow_id, token) = token_of(&resp);
    for _ in 0..FLOW_MAX_ATTEMPTS {
        let r = d.complete_flow(
            &token,
            FlowCompletion::Unlocked {
                credential_id: CRED.into(),
                prf_output: crypto::b64url(&[0u8; 32]),
                duration_secs: Some(60),
            },
        );
        assert!(r.is_err());
    }
    assert_eq!(d.flow_info(&token).unwrap_err().code, ErrorCode::NotFound);
    let (resp, _) = d.handle(Request::FlowStatus { flow_id }).unwrap();
    assert!(matches!(
        resp,
        Response::FlowState {
            state: FlowState::Failed { .. }
        }
    ));
}

#[test]
fn enroll_adds_a_second_passkey_that_unlocks() {
    let dir = tempfile::tempdir().unwrap();
    let d = daemon();
    let prf = [5u8; 32];
    let path = setup_vault(&d, dir.path(), &prf);
    let e = d
        .handle(Request::Enroll {
            vault_path: path.clone(),
            label: None,
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Locked);
    unlock(&d, &path, &prf, Some(600)).unwrap();
    let (resp, _) = d
        .handle(Request::Enroll {
            vault_path: path.clone(),
            label: Some("Backup".into()),
        })
        .unwrap();
    let (_, token) = token_of(&resp);
    let proto::FlowInfo::Enroll(info) = d.flow_info(&token).unwrap() else {
        panic!()
    };
    assert_eq!(info.exclude_credentials, vec![CRED.to_owned()]);
    let prf2 = [6u8; 32];
    d.complete_flow(
        &token,
        FlowCompletion::Registered {
            credential_id: "c2Vjb25k".into(),
            prf_output: crypto::b64url(&prf2),
            label: String::new(),
        },
    )
    .unwrap();
    let v = Vault::load(&path).unwrap();
    assert_eq!(v.file.passkeys.len(), 2);
    assert_eq!(v.file.passkeys[1].label, "Backup");
    d.lock_all("test");
    let (resp, _) = d
        .handle(Request::Unlock {
            vault_path: path.clone(),
            suggest_secs: None,
        })
        .unwrap();
    let (_, token) = token_of(&resp);
    d.complete_flow(
        &token,
        FlowCompletion::Unlocked {
            credential_id: "c2Vjb25k".into(),
            prf_output: crypto::b64url(&prf2),
            duration_secs: None,
        },
    )
    .unwrap();
    assert_eq!(d.statuses().len(), 1);
}

#[test]
fn setup_refuses_existing_file_and_wrong_flow_kinds() {
    let dir = tempfile::tempdir().unwrap();
    let d = daemon();
    let prf = [9u8; 32];
    let path = setup_vault(&d, dir.path(), &prf);
    assert!(d
        .handle(Request::Setup {
            vault_path: path.clone(),
            name: None,
            label: None
        })
        .is_err());
    let (resp, _) = d
        .handle(Request::Unlock {
            vault_path: path.clone(),
            suggest_secs: None,
        })
        .unwrap();
    let (_, token) = token_of(&resp);
    let e = d
        .complete_flow(
            &token,
            FlowCompletion::Registered {
                credential_id: CRED.into(),
                prf_output: crypto::b64url(&prf),
                label: "x".into(),
            },
        )
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid);
}

#[test]
fn new_unlock_request_supersedes_old_link() {
    let dir = tempfile::tempdir().unwrap();
    let d = daemon();
    let path = setup_vault(&d, dir.path(), &[1u8; 32]);
    let req = || Request::Unlock {
        vault_path: path.clone(),
        suggest_secs: None,
    };
    let (r1, _) = d.handle(req()).unwrap();
    let (_, t1) = token_of(&r1);
    let (r2, _) = d.handle(req()).unwrap();
    let (_, t2) = token_of(&r2);
    assert!(d.flow_info(&t1).is_err());
    assert!(d.flow_info(&t2).is_ok());
}
