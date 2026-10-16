//! agentpass web UI: passkey registration (setup / enroll), unlocking, the
//! secrets editor and secret requests.
//!
//! The one-time flow token arrives in the URL fragment, is removed from the
//! address bar immediately and is sent to the daemon in a header.

mod api;
mod duration;
mod editor;
mod tree;
mod webauthn;

use agentpass_protocol::{FlowCompletion, FlowInfo, RegisterInfo, UnlockInfo, VaultSummary};
use yew::prelude::*;

use duration::{DurationChoice, DurationPicker};

#[derive(Clone, PartialEq)]
enum Phase {
    Loading,
    Ready(Box<FlowInfo>),
    Done(String),
    Fatal(String),
}

/// The flow token: from the URL fragment (then removed from the address
/// bar and kept in this tab's sessionStorage), or from sessionStorage after
/// a reload.
fn take_token() -> Option<String> {
    let window = web_sys::window()?;
    let path = window.location().pathname().unwrap_or_default();
    let storage = window.session_storage().ok().flatten();
    let key = format!("agentpass-token:{path}");
    let hash = window.location().hash().ok().unwrap_or_default();
    let fresh = hash.trim_start_matches('#').to_owned();
    if !fresh.is_empty() {
        if let Some(st) = &storage {
            let _ = st.set_item(&key, &fresh);
        }
        if let Ok(history) = window.history() {
            let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(&path));
        }
        return Some(fresh);
    }
    storage
        .and_then(|st| st.get_item(&key).ok().flatten())
        .filter(|t| !t.is_empty())
}

#[function_component(App)]
fn app() -> Html {
    let token = use_state(take_token);
    let phase = use_state(|| Phase::Loading);

    {
        let phase = phase.clone();
        let token = (*token).clone();
        use_effect_with((), move |_| match token {
            None => phase.set(Phase::Fatal(
                "This page needs the full link printed by agentpass (including the part after #)."
                    .into(),
            )),
            Some(token) => wasm_bindgen_futures::spawn_local(async move {
                match api::flow_info(&token).await {
                    Ok(info) => phase.set(Phase::Ready(Box::new(info))),
                    Err(e) => phase.set(Phase::Fatal(e)),
                }
            }),
        });
    }

    let on_done = {
        let phase = phase.clone();
        Callback::from(move |msg: String| phase.set(Phase::Done(msg)))
    };
    let token = (*token).clone().unwrap_or_default();

    let body = match &*phase {
        Phase::Loading => html! { <p class="muted">{ "> loading…" }</p> },
        Phase::Fatal(msg) => html! {
            <>
                <h1>{ "Link not usable" }</h1>
                <p class="error">{ msg }</p>
                <p class="muted">{ "Ask your agent to run the command again for a fresh link." }</p>
            </>
        },
        Phase::Done(msg) => html! {
            <div class="done">
                <div class="check" aria-hidden="true">{ "[ OK ]" }</div>
                <h1>{ "All set" }</h1>
                <p>{ msg }</p>
                <p class="muted">{ "You can close this tab and return to your agent." }</p>
            </div>
        },
        Phase::Ready(flow) => match &**flow {
            FlowInfo::Setup(info) => html! {
                <Register info={info.clone()} token={token.clone()} on_done={on_done.clone()} setup=true />
            },
            FlowInfo::Enroll(info) => html! {
                <Register info={info.clone()} token={token.clone()} on_done={on_done.clone()} setup=false />
            },
            FlowInfo::Edit(info) => html! {
                <editor::Editor info={info.clone()} token={token.clone()} on_done={on_done.clone()} />
            },
            FlowInfo::Request(info) => html! {
                <editor::RequestView info={info.clone()} token={token.clone()} on_done={on_done.clone()} />
            },
            FlowInfo::Unlock(info) => html! {
                <Unlock info={info.clone()} token={token.clone()} on_done={on_done.clone()} />
            },
        },
    };

    let wide = matches!(&*phase, Phase::Ready(f) if matches!(**f, FlowInfo::Edit(_)));
    html! {
        <main class={classes!(wide.then_some("wide"))}>
            <header class="brand">
                <span class="logo" aria-hidden="true">{ "🔐" }</span>
                <span>{ "agentpass" }</span>
                <span class="cursor" aria-hidden="true">{ "_" }</span>
            </header>
            <section class="card">{ body }</section>
            <footer class="muted">
                { "Served by your local agentpass daemon. Secrets never leave this machine." }
            </footer>
        </main>
    }
}

#[derive(Properties, PartialEq)]
pub struct VaultCardProps {
    pub vault: VaultSummary,
    /// Also draw the read-only secrets tree.
    #[prop_or(true)]
    pub tree: bool,
}

#[function_component(VaultCard)]
pub fn vault_card(props: &VaultCardProps) -> Html {
    let v = &props.vault;
    html! {
        <>
        <dl class="vault">
            <dt>{ "Vault" }</dt><dd><strong>{ &v.name }</strong></dd>
            <dt>{ "File" }</dt><dd><code>{ &v.path }</code></dd>
        </dl>
        if props.tree && !v.vault_id.is_empty() {
            <tree::SecretsTree secrets={v.secrets.clone()} />
        }
        </>
    }
}

#[derive(Properties, PartialEq)]
struct RegisterProps {
    info: RegisterInfo,
    token: String,
    on_done: Callback<String>,
    setup: bool,
}

#[function_component(Register)]
fn register(props: &RegisterProps) -> Html {
    let label = use_state(|| props.info.suggested_label.clone());
    let busy = use_state(|| false);
    let error = use_state(|| None::<String>);

    let oninput = {
        let label = label.clone();
        Callback::from(move |e: InputEvent| {
            let input: web_sys::HtmlInputElement = e.target_unchecked_into();
            label.set(input.value());
        })
    };

    let onsubmit = {
        let (label, busy, error) = (label.clone(), busy.clone(), error.clone());
        let info = props.info.clone();
        let token = props.token.clone();
        let on_done = props.on_done.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            if *busy {
                return;
            }
            busy.set(true);
            error.set(None);
            let (label, busy, error) = ((*label).clone(), busy.clone(), error.clone());
            let (info, token, on_done) = (info.clone(), token.clone(), on_done.clone());
            wasm_bindgen_futures::spawn_local(async move {
                let result = async {
                    let cred = webauthn::register(&info).await?;
                    api::complete(
                        &token,
                        &FlowCompletion::Registered {
                            credential_id: cred.credential_id,
                            prf_output: cred.prf_output,
                            label,
                        },
                    )
                    .await
                }
                .await;
                busy.set(false);
                match result {
                    Ok(msg) => on_done.emit(msg),
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    let (title, intro, button) = if props.setup {
        (
            "Create your vault",
            "Register a passkey to protect this vault. Only its PRF secret is used: \
             it decrypts the vault key, so nothing secret is stored unencrypted.",
            "Create passkey",
        )
    } else {
        (
            "Add a passkey",
            "Register another passkey (for example a backup security key) that can unlock this vault.",
            "Add passkey",
        )
    };

    html! {
        <form {onsubmit}>
            <h1>{ title }</h1>
            <p>{ intro }</p>
            <VaultCard vault={props.info.vault.clone()} />
            <label class="field">
                <span>{ "Passkey label" }</span>
                <input type="text" maxlength="64" value={(*label).clone()} {oninput} />
                <small class="muted">{ "Helps you tell passkeys apart, e.g. “YubiKey 5C” or “1Password”." }</small>
            </label>
            if let Some(e) = &*error { <p class="error" role="alert">{ e }</p> }
            <button type="submit" class="primary" disabled={*busy}>
                { if *busy { "Waiting for passkey…" } else { button } }
            </button>
            <p class="hint muted">
                { "Use a security key, your platform authenticator or a password manager that supports the WebAuthn PRF extension. You may be asked twice." }
            </p>
        </form>
    }
}

#[derive(Properties, PartialEq)]
struct UnlockProps {
    info: UnlockInfo,
    token: String,
    on_done: Callback<String>,
}

#[function_component(Unlock)]
fn unlock(props: &UnlockProps) -> Html {
    let choice = use_state(|| DurationChoice::from_suggestion(props.info.suggested_duration_secs));
    let busy = use_state(|| false);
    let error = use_state(|| None::<String>);
    let max = props.info.max_duration_secs;

    let onchange = {
        let choice = choice.clone();
        Callback::from(move |c: DurationChoice| choice.set(c))
    };

    let valid = choice.seconds(max);
    let onsubmit = {
        let (busy, error) = (busy.clone(), error.clone());
        let info = props.info.clone();
        let token = props.token.clone();
        let on_done = props.on_done.clone();
        let valid = valid.clone();
        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();
            if *busy {
                return;
            }
            let duration_secs = match &valid {
                Ok(d) => *d,
                Err(msg) => {
                    error.set(Some(msg.clone()));
                    return;
                }
            };
            busy.set(true);
            error.set(None);
            let (busy, error) = (busy.clone(), error.clone());
            let (info, token, on_done) = (info.clone(), token.clone(), on_done.clone());
            wasm_bindgen_futures::spawn_local(async move {
                let result = async {
                    let out = webauthn::evaluate(&info).await?;
                    api::complete(
                        &token,
                        &FlowCompletion::Unlocked {
                            credential_id: out.credential_id,
                            prf_output: out.prf_output,
                            duration_secs,
                        },
                    )
                    .await
                }
                .await;
                busy.set(false);
                match result {
                    Ok(msg) => on_done.emit(msg),
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    let suggestion = match props.info.suggested_duration_secs {
        Some(0) => Some("Your agent suggested: until locked".to_owned()),
        Some(s) => Some(format!("Your agent suggested: {}", duration::describe(s))),
        None => None,
    };

    html! {
        <form {onsubmit}>
            <h1>{ "Unlock vault" }</h1>
            <p>{ "An agent asked to use the secrets in this vault. Choose how long it stays unlocked, then confirm with your passkey." }</p>
            <VaultCard vault={props.info.vault.clone()} />
            <fieldset>
                <legend>{ "Keep unlocked for" }</legend>
                <DurationPicker value={(*choice).clone()} {onchange} {max} />
                if let Some(s) = suggestion { <small class="muted">{ s }</small> }
            </fieldset>
            if let Some(e) = &*error { <p class="error" role="alert">{ e }</p> }
            <button type="submit" class="primary" disabled={*busy || valid.is_err()}>
                { if *busy { "Waiting for passkey…" } else { "Unlock with passkey" } }
            </button>
            <p class="hint muted">
                { "While unlocked, programs running as your user can read these secrets through agentpass. Run " }
                <code>{ "agentpass lock" }</code>
                { " to lock early. Sleep, logout and reboot always lock." }
            </p>
        </form>
    }
}

fn main() {
    // A new link in the same tab only changes the fragment: start over.
    if let Some(window) = web_sys::window() {
        let reload = wasm_bindgen::closure::Closure::<dyn Fn()>::new(|| {
            if let Some(w) = web_sys::window() {
                let _ = w.location().reload();
            }
        });
        window.set_onhashchange(Some(wasm_bindgen::JsCast::unchecked_ref(reload.as_ref())));
        reload.forget();
    }
    yew::Renderer::<App>::new().render();
}
