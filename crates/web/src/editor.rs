//! The secrets editor (`agentpass edit`) and the request view
//! (`agentpass request`). Both are built on the interactive tree.
//!
//! The editor collects changes locally and saves them as one atomic batch.
//! Existing values are never sent to the page; a value field left empty
//! keeps the stored value.

use agentpass_protocol::{EditInfo, EditOp, FlowCompletion, RequestInfo, SecretSummary};
use yew::prelude::*;

use crate::tree::{Clicked, Item, Status, TreeView};
use crate::{api, webauthn, VaultCard};

// ---- model -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct Entry {
    /// Key and description as stored (None for new secrets).
    orig: Option<(String, Option<String>)>,
    key: String,
    description: Option<String>,
    /// New value, if the user typed one.
    value: Option<String>,
    deleted: bool,
}

impl Entry {
    fn status(&self) -> Status {
        match &self.orig {
            _ if self.deleted => Status::Deleted,
            None => Status::New,
            Some((k, d)) if *k != self.key || *d != self.description || self.value.is_some() => {
                Status::Changed
            }
            Some(_) => Status::Normal,
        }
    }
}

fn entries_from(secrets: &[SecretSummary]) -> Vec<Entry> {
    secrets
        .iter()
        .map(|s| Entry {
            orig: Some((s.key.clone(), s.description.clone())),
            key: s.key.clone(),
            description: s.description.clone(),
            value: None,
            deleted: false,
        })
        .collect()
}

/// The batch of operations that turns the stored vault into `entries`.
fn ops_for(entries: &[Entry]) -> Vec<EditOp> {
    let mut ops = Vec::new();
    for e in entries {
        match (&e.orig, e.deleted) {
            (Some((k, _)), true) => ops.push(EditOp::Delete { key: k.clone() }),
            (None, true) => {}
            (Some((k, d)), false) => {
                if *k != e.key {
                    ops.push(EditOp::Rename {
                        from: k.clone(),
                        to: e.key.clone(),
                    });
                }
                if e.value.is_some() || *d != e.description {
                    ops.push(EditOp::Put {
                        key: e.key.clone(),
                        value: e.value.clone(),
                        description: Some(e.description.clone().unwrap_or_default()),
                    });
                }
            }
            (None, false) => ops.push(EditOp::Put {
                key: e.key.clone(),
                value: e.value.clone(),
                description: e.description.clone(),
            }),
        }
    }
    ops
}

fn split_key(key: &str) -> (String, String) {
    match key.rsplit_once('/') {
        Some((f, n)) => (f.to_owned(), n.to_owned()),
        None => (String::new(), key.to_owned()),
    }
}

fn join_key(folder: &str, name: &str) -> String {
    let folder = folder.trim().trim_matches('/');
    let name = name.trim();
    if folder.is_empty() {
        name.to_owned()
    } else {
        format!("{folder}/{name}")
    }
}

fn valid_key(key: &str) -> bool {
    key.len() <= 128
        && key.split('/').all(|s| {
            !s.is_empty()
                && !s.starts_with(['.', '-'])
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        })
}

fn folders_of(entries: &[Entry], extra: &[String]) -> Vec<String> {
    let mut out: Vec<String> = extra.to_vec();
    for e in entries.iter().filter(|e| !e.deleted) {
        let parts: Vec<&str> = e.key.split('/').collect();
        for i in 1..parts.len() {
            out.push(parts[..i].join("/"));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn input_value(e: &InputEvent) -> String {
    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
    input.value()
}

// ---- secret form ------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Draft {
    pub folder: String,
    pub name: String,
    pub description: String,
    pub value: String,
}

impl Draft {
    fn key(&self) -> String {
        join_key(&self.folder, &self.name)
    }
}

#[derive(Properties, PartialEq)]
struct FormProps {
    draft: Draft,
    on_change: Callback<Draft>,
    folders: Vec<String>,
    /// Placeholder for the value field ("unchanged" for existing secrets).
    value_placeholder: AttrValue,
}

#[function_component(SecretForm)]
fn secret_form(props: &FormProps) -> Html {
    let field = |f: fn(&mut Draft, String)| {
        let (draft, cb) = (props.draft.clone(), props.on_change.clone());
        Callback::from(move |e: InputEvent| {
            let mut d = draft.clone();
            f(&mut d, input_value(&e));
            cb.emit(d);
        })
    };
    let key = props.draft.key();
    let key_ok = valid_key(&key);
    html! {
        <div class="form">
            <label class="field">
                <span>{ "Folder" }</span>
                <input type="text" aria-label="Folder" list="folders" placeholder="(top level)" autocomplete="off" spellcheck="false"
                    value={props.draft.folder.clone()} oninput={field(|d, v| d.folder = v)} />
                <datalist id="folders">
                    { for props.folders.iter().map(|f| html! { <option value={f.clone()} /> }) }
                </datalist>
            </label>
            <label class="field">
                <span>{ "Name" }</span>
                <input type="text" aria-label="Name" placeholder="DB_PASSWORD" autocomplete="off" spellcheck="false"
                    value={props.draft.name.clone()} oninput={field(|d, v| d.name = v)} />
                <small class={classes!(if key_ok { "muted" } else { "error-text" })}>
                    { if key_ok { format!("→ {key}") } else { "letters, digits, _ . - ; folders separated by /".to_owned() } }
                </small>
            </label>
            <label class="field">
                <span>{ "Description" }</span>
                <input type="text" aria-label="Description" placeholder="(optional)" maxlength="200"
                    value={props.draft.description.clone()} oninput={field(|d, v| d.description = v)} />
            </label>
            <label class="field">
                <span>{ "Value" }</span>
                <input type="password" aria-label="Value" autocomplete="off" placeholder={props.value_placeholder.clone()}
                    value={props.draft.value.clone()} oninput={field(|d, v| d.value = v)} />
            </label>
        </div>
    }
}

// ---- editor -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Selection {
    None,
    Secret(usize, Draft),
    New(Draft),
    Folder { path: String, rename: String },
    NewFolder(String),
}

#[derive(Properties, PartialEq)]
pub struct EditorProps {
    pub info: EditInfo,
    pub token: String,
    pub on_done: Callback<String>,
}

#[function_component(Editor)]
pub fn editor(props: &EditorProps) -> Html {
    let authed = use_state(|| false);
    let vault = use_state(|| props.info.vault.clone());
    let entries = use_state(|| entries_from(&props.info.vault.secrets));
    let extra = use_state(Vec::<String>::new);
    let sel = use_state(|| Selection::None);
    let busy = use_state(|| false);
    let error = use_state(|| None::<String>);
    let notice = use_state(|| None::<String>);

    if !*authed {
        let onclick = {
            let (authed, busy, error) = (authed.clone(), busy.clone(), error.clone());
            let (info, token) = (props.info.clone(), props.token.clone());
            Callback::from(move |_| {
                busy.set(true);
                error.set(None);
                let (authed, busy, error, info, token) = (
                    authed.clone(),
                    busy.clone(),
                    error.clone(),
                    info.clone(),
                    token.clone(),
                );
                wasm_bindgen_futures::spawn_local(async move {
                    let r = async {
                        let out = webauthn::evaluate(&info).await?;
                        api::complete(
                            &token,
                            &FlowCompletion::EditAuth {
                                credential_id: out.credential_id,
                                prf_output: out.prf_output,
                            },
                        )
                        .await
                    }
                    .await;
                    busy.set(false);
                    match r {
                        Ok(_) => authed.set(true),
                        Err(e) => error.set(Some(e)),
                    }
                });
            })
        };
        return html! {
            <>
                <h1>{ "Edit secrets" }</h1>
                <p>{ "Confirm with your passkey to add, change, rename or delete secrets and folders." }</p>
                <VaultCard vault={(*vault).clone()} />
                if let Some(e) = &*error { <p class="error" role="alert">{ e }</p> }
                <button class="primary" {onclick} disabled={*busy}>
                    { if *busy { "Waiting for passkey…" } else { "Open editor with passkey" } }
                </button>
                <p class="hint muted">{ "Opening the editor does not unlock the vault for agents. Existing values are never shown." }</p>
            </>
        };
    }

    let folders = folders_of(&entries, &extra);
    let items: Vec<Item> = entries
        .iter()
        .map(|e| Item {
            key: e.key.clone(),
            description: e.description.clone(),
            status: e.status(),
        })
        .chain(match &*sel {
            Selection::New(d) if valid_key(&d.key()) => Some(Item {
                key: d.key(),
                description: None,
                status: Status::New,
            }),
            _ => None,
        })
        .collect();
    let pending = ops_for(&entries).len();
    let selected = match &*sel {
        Selection::Secret(i, _) => entries.get(*i).map(|e| e.key.clone()),
        Selection::Folder { path, .. } => Some(path.clone()),
        Selection::New(d) => Some(d.key()),
        _ => None,
    };

    let on_click = {
        let (sel, entries) = (sel.clone(), entries.clone());
        Callback::from(move |c: Clicked| match c {
            Clicked::Secret(key) => {
                if let Some(i) = entries.iter().position(|e| e.key == key) {
                    let e = &entries[i];
                    let (folder, name) = split_key(&e.key);
                    sel.set(Selection::Secret(
                        i,
                        Draft {
                            folder,
                            name,
                            description: e.description.clone().unwrap_or_default(),
                            value: e.value.clone().unwrap_or_default(),
                        },
                    ));
                }
            }
            Clicked::Folder(path) => sel.set(Selection::Folder {
                rename: path.clone(),
                path,
            }),
        })
    };
    let set_sel = |s: Selection| {
        let sel = sel.clone();
        Callback::from(move |_: MouseEvent| sel.set(s.clone()))
    };

    let panel = match &*sel {
        Selection::None => html! {
            <p class="muted">{ "Select a secret or folder in the tree, or add a new one." }</p>
        },
        Selection::Secret(i, draft) => {
            let i = *i;
            let entry = entries[i].clone();
            let on_change = {
                let sel = sel.clone();
                Callback::from(move |d| sel.set(Selection::Secret(i, d)))
            };
            let apply = {
                let (entries, sel, draft, error) =
                    (entries.clone(), sel.clone(), draft.clone(), error.clone());
                Callback::from(move |_: MouseEvent| {
                    let key = draft.key();
                    if !valid_key(&key) {
                        error.set(Some(format!("invalid name {key:?}")));
                        return;
                    }
                    if entries
                        .iter()
                        .enumerate()
                        .any(|(j, e)| j != i && !e.deleted && e.key == key)
                    {
                        error.set(Some(format!("{key} already exists")));
                        return;
                    }
                    let mut list = (*entries).clone();
                    let e = &mut list[i];
                    e.key = key;
                    e.description =
                        Some(draft.description.trim().to_owned()).filter(|d| !d.is_empty());
                    e.value = Some(draft.value.clone()).filter(|v| !v.is_empty());
                    error.set(None);
                    entries.set(list);
                    sel.set(Selection::None);
                })
            };
            let toggle_delete = {
                let (entries, sel) = (entries.clone(), sel.clone());
                Callback::from(move |_: MouseEvent| {
                    let mut list = (*entries).clone();
                    if list[i].orig.is_none() {
                        list.remove(i);
                    } else {
                        list[i].deleted = !list[i].deleted;
                    }
                    entries.set(list);
                    sel.set(Selection::None);
                })
            };
            html! {
                <>
                    <h2>{ if entry.orig.is_some() { format!("secret: {}", entry.orig.as_ref().unwrap().0) } else { "new secret".to_owned() } }</h2>
                    <SecretForm draft={draft.clone()} {on_change} folders={folders.clone()}
                        value_placeholder={if entry.orig.is_some() { "(unchanged)" } else { "required" }} />
                    <div class="actions">
                        <button class="btn" onclick={apply}>{ "Apply" }</button>
                        <button class="btn danger" onclick={toggle_delete}>{ if entry.deleted { "Restore" } else { "Delete" } }</button>
                        <button class="btn ghost" onclick={set_sel(Selection::None)}>{ "Cancel" }</button>
                    </div>
                </>
            }
        }
        Selection::New(draft) => {
            let on_change = {
                let sel = sel.clone();
                Callback::from(move |d| sel.set(Selection::New(d)))
            };
            let add = {
                let (entries, sel, draft, error) =
                    (entries.clone(), sel.clone(), draft.clone(), error.clone());
                Callback::from(move |_: MouseEvent| {
                    let key = draft.key();
                    if !valid_key(&key) {
                        error.set(Some(format!("invalid name {key:?}")));
                        return;
                    }
                    if draft.value.is_empty() {
                        error.set(Some("a new secret needs a value".into()));
                        return;
                    }
                    let mut list = (*entries).clone();
                    if let Some(e) = list.iter_mut().find(|e| e.key == key && !e.deleted) {
                        // Same name as an existing secret: override its value.
                        e.value = Some(draft.value.clone());
                        if !draft.description.trim().is_empty() {
                            e.description = Some(draft.description.trim().to_owned());
                        }
                    } else {
                        list.push(Entry {
                            orig: None,
                            key,
                            description: Some(draft.description.trim().to_owned())
                                .filter(|d| !d.is_empty()),
                            value: Some(draft.value.clone()),
                            deleted: false,
                        });
                    }
                    error.set(None);
                    entries.set(list);
                    sel.set(Selection::None);
                })
            };
            html! {
                <>
                    <h2>{ "new secret" }</h2>
                    <SecretForm draft={draft.clone()} {on_change} folders={folders.clone()} value_placeholder="required" />
                    <div class="actions">
                        <button class="btn" onclick={add}>{ "Add" }</button>
                        <button class="btn ghost" onclick={set_sel(Selection::None)}>{ "Cancel" }</button>
                    </div>
                </>
            }
        }
        Selection::Folder { path, rename } => {
            let path = path.clone();
            let oninput = {
                let (sel, path) = (sel.clone(), path.clone());
                Callback::from(move |e: InputEvent| {
                    sel.set(Selection::Folder {
                        path: path.clone(),
                        rename: input_value(&e),
                    })
                })
            };
            let in_folder = |k: &str, p: &str| k.starts_with(&format!("{p}/"));
            let do_rename = {
                let (entries, extra, sel, error, path, rename) = (
                    entries.clone(),
                    extra.clone(),
                    sel.clone(),
                    error.clone(),
                    path.clone(),
                    rename.clone(),
                );
                Callback::from(move |_: MouseEvent| {
                    let to = rename.trim().trim_matches('/').to_owned();
                    if to == path {
                        sel.set(Selection::None);
                        return;
                    }
                    if !valid_key(&to) {
                        error.set(Some(format!("invalid folder name {to:?}")));
                        return;
                    }
                    let mut list = (*entries).clone();
                    for e in list
                        .iter_mut()
                        .filter(|e| !e.deleted && in_folder(&e.key, &path))
                    {
                        e.key = format!("{to}{}", &e.key[path.len()..]);
                    }
                    let mut seen = std::collections::HashSet::new();
                    if let Some(dup) = list
                        .iter()
                        .filter(|e| !e.deleted)
                        .find(|e| !seen.insert(e.key.clone()))
                    {
                        error.set(Some(format!("{} would exist twice", dup.key)));
                        return;
                    }
                    extra.set(
                        extra
                            .iter()
                            .map(|f| {
                                if *f == path || in_folder(f, &path) {
                                    format!("{to}{}", &f[path.len()..])
                                } else {
                                    f.clone()
                                }
                            })
                            .collect(),
                    );
                    error.set(None);
                    entries.set(list);
                    sel.set(Selection::None);
                })
            };
            let do_delete = {
                let (entries, extra, sel, path) =
                    (entries.clone(), extra.clone(), sel.clone(), path.clone());
                Callback::from(move |_: MouseEvent| {
                    let mut list: Vec<Entry> = (*entries).clone();
                    list.retain(|e| e.orig.is_some() || !in_folder(&e.key, &path));
                    for e in list.iter_mut().filter(|e| in_folder(&e.key, &path)) {
                        e.deleted = true;
                    }
                    entries.set(list);
                    extra.set(
                        extra
                            .iter()
                            .filter(|f| **f != path && !in_folder(f, &path))
                            .cloned()
                            .collect(),
                    );
                    sel.set(Selection::None);
                })
            };
            let n = entries
                .iter()
                .filter(|e| !e.deleted && in_folder(&e.key, &path))
                .count();
            html! {
                <>
                    <h2>{ format!("folder: {path}/") }</h2>
                    <p class="muted">{ format!("{n} secret{} inside", if n == 1 { "" } else { "s" }) }</p>
                    <label class="field">
                        <span>{ "Rename / move to" }</span>
                        <input type="text" spellcheck="false" value={rename.clone()} {oninput} />
                    </label>
                    <div class="actions">
                        <button class="btn" onclick={do_rename}>{ "Rename" }</button>
                        <button class="btn" onclick={set_sel(Selection::New(Draft { folder: path.clone(), ..Draft::default() }))}>{ "+ secret here" }</button>
                        <button class="btn danger" onclick={do_delete}>{ "Delete folder" }</button>
                        <button class="btn ghost" onclick={set_sel(Selection::None)}>{ "Cancel" }</button>
                    </div>
                </>
            }
        }
        Selection::NewFolder(name) => {
            let oninput = {
                let sel = sel.clone();
                Callback::from(move |e: InputEvent| sel.set(Selection::NewFolder(input_value(&e))))
            };
            let create = {
                let (extra, sel, error, name) =
                    (extra.clone(), sel.clone(), error.clone(), name.clone());
                Callback::from(move |_: MouseEvent| {
                    let path = name.trim().trim_matches('/').to_owned();
                    if !valid_key(&path) {
                        error.set(Some(format!("invalid folder name {path:?}")));
                        return;
                    }
                    let mut list = (*extra).clone();
                    list.push(path.clone());
                    extra.set(list);
                    error.set(None);
                    sel.set(Selection::New(Draft {
                        folder: path,
                        ..Draft::default()
                    }));
                })
            };
            html! {
                <>
                    <h2>{ "new folder" }</h2>
                    <label class="field">
                        <span>{ "Folder path" }</span>
                        <input type="text" placeholder="production/aws" spellcheck="false" value={name.clone()} {oninput} />
                        <small class="muted">{ "Folders are saved once they contain a secret." }</small>
                    </label>
                    <div class="actions">
                        <button class="btn" onclick={create}>{ "Create" }</button>
                        <button class="btn ghost" onclick={set_sel(Selection::None)}>{ "Cancel" }</button>
                    </div>
                </>
            }
        }
    };

    let save = {
        let (entries, extra, vault, busy, error, notice, sel, token) = (
            entries.clone(),
            extra.clone(),
            vault.clone(),
            busy.clone(),
            error.clone(),
            notice.clone(),
            sel.clone(),
            props.token.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            let ops = ops_for(&entries);
            if ops.is_empty() {
                return;
            }
            busy.set(true);
            let (entries, extra, vault, busy, error, notice, sel, token) = (
                entries.clone(),
                extra.clone(),
                vault.clone(),
                busy.clone(),
                error.clone(),
                notice.clone(),
                sel.clone(),
                token.clone(),
            );
            wasm_bindgen_futures::spawn_local(async move {
                let r = api::edit(&token, ops).await;
                busy.set(false);
                match r {
                    Ok(res) => {
                        entries.set(entries_from(&res.vault.secrets));
                        let folders = folders_of(&entries_from(&res.vault.secrets), &[]);
                        extra.set(
                            extra
                                .iter()
                                .filter(|f| !folders.contains(f))
                                .cloned()
                                .collect(),
                        );
                        vault.set(res.vault);
                        sel.set(Selection::None);
                        error.set(None);
                        notice.set(Some(res.message));
                    }
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };
    let discard = {
        let (entries, extra, sel, vault, notice) = (
            entries.clone(),
            extra.clone(),
            sel.clone(),
            vault.clone(),
            notice.clone(),
        );
        Callback::from(move |_: MouseEvent| {
            entries.set(entries_from(&vault.secrets));
            extra.set(vec![]);
            sel.set(Selection::None);
            notice.set(None);
        })
    };
    let done = {
        let (token, on_done, error) = (props.token.clone(), props.on_done.clone(), error.clone());
        Callback::from(move |_: MouseEvent| {
            let (token, on_done, error) = (token.clone(), on_done.clone(), error.clone());
            wasm_bindgen_futures::spawn_local(async move {
                match api::complete(&token, &FlowCompletion::EditClosed).await {
                    Ok(msg) => on_done.emit(msg),
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    html! {
        <>
            <h1>{ "Edit secrets" }</h1>
            <VaultCard vault={(*vault).clone()} tree=false />
            <div class="toolbar">
                <button class="btn" onclick={set_sel(Selection::New(Draft::default()))}>{ "+ secret" }</button>
                <button class="btn" onclick={set_sel(Selection::NewFolder(String::new()))}>{ "+ folder" }</button>
            </div>
            <TreeView {items} extra_folders={(*extra).clone()} {selected} on_click={Some(on_click)} summary=true />
            <section class="panel">{ panel }</section>
            if let Some(e) = &*error { <p class="error" role="alert">{ e }</p> }
            if let Some(n) = &*notice { if pending == 0 { <p class="notice">{ n }</p> } }
            <div class="savebar">
                <span class="muted">{ match pending { 0 => "no unsaved changes".to_owned(), 1 => "1 unsaved change".to_owned(), n => format!("{n} unsaved changes") } }</span>
                <button class="btn ghost" onclick={discard} disabled={pending == 0 || *busy}>{ "Discard" }</button>
                <button class="primary small" onclick={save} disabled={pending == 0 || *busy}>{ if *busy { "Saving…" } else { "Save" } }</button>
            </div>
            <button class="btn ghost wide" onclick={done} disabled={pending > 0}>
                { if pending > 0 { "Save or discard before closing" } else { "Done: close editor" } }
            </button>
        </>
    }
}

// ---- request ----------------------------------------------------------------

#[derive(Properties, PartialEq)]
pub struct RequestProps {
    pub info: RequestInfo,
    pub token: String,
    pub on_done: Callback<String>,
}

#[function_component(RequestView)]
pub fn request_view(props: &RequestProps) -> Html {
    let draft = use_state(|| {
        let (folder, name) = split_key(&props.info.key);
        Draft {
            folder,
            name,
            description: props.info.description.clone().unwrap_or_default(),
            value: String::new(),
        }
    });
    let replace = use_state(|| false);
    let busy = use_state(|| false);
    let error = use_state(|| None::<String>);

    let key = draft.key();
    let exists = props.info.vault.secrets.iter().any(|s| s.key == key);
    let mut items: Vec<Item> = props.info.vault.secrets.iter().map(Item::from).collect();
    if valid_key(&key) {
        match items.iter_mut().find(|i| i.key == key) {
            Some(i) => i.status = Status::Changed,
            None => items.push(Item {
                key: key.clone(),
                description: Some(draft.description.clone()).filter(|d| !d.is_empty()),
                status: Status::New,
            }),
        }
    }
    let folders = folders_of(&entries_from(&props.info.vault.secrets), &[]);
    let on_change = {
        let draft = draft.clone();
        Callback::from(move |d| draft.set(d))
    };
    let on_replace = {
        let replace = replace.clone();
        Callback::from(move |_: Event| replace.set(!*replace))
    };

    let submit = |declined: bool| {
        let (draft, replace, busy, error, token, on_done) = (
            draft.clone(),
            replace.clone(),
            busy.clone(),
            error.clone(),
            props.token.clone(),
            props.on_done.clone(),
        );
        Callback::from(move |e: MouseEvent| {
            e.prevent_default();
            let completion = if declined {
                FlowCompletion::Declined
            } else {
                let key = draft.key();
                if !valid_key(&key) {
                    error.set(Some(format!("invalid name {key:?}")));
                    return;
                }
                if draft.value.is_empty() {
                    error.set(Some("enter the value".into()));
                    return;
                }
                FlowCompletion::Provided {
                    key,
                    description: Some(draft.description.trim().to_owned())
                        .filter(|d| !d.is_empty()),
                    value: draft.value.clone(),
                    replace: *replace,
                }
            };
            busy.set(true);
            let (busy, error, token, on_done) =
                (busy.clone(), error.clone(), token.clone(), on_done.clone());
            wasm_bindgen_futures::spawn_local(async move {
                let r = api::complete(&token, &completion).await;
                busy.set(false);
                match r {
                    Ok(msg) => on_done.emit(msg),
                    Err(e) => error.set(Some(e)),
                }
            });
        })
    };

    html! {
        <form>
            <h1>{ "Secret requested" }</h1>
            <p>{ "An agent asked you to add a secret. Name, folder and description are suggestions; change them as you like." }</p>
            if let Some(r) = &props.info.reason {
                <p class="reason">{ format!("“{r}”") }</p>
            }
            <VaultCard vault={props.info.vault.clone()} tree=false />
            <TreeView {items} selected={Some(key.clone())} summary=false />
            <SecretForm draft={(*draft).clone()} {on_change} {folders} value_placeholder="paste the secret" />
            if exists {
                <label class="check-line">
                    <input type="checkbox" checked={*replace} onchange={on_replace} />
                    { format!(" replace the existing {key}") }
                </label>
            }
            if let Some(e) = &*error { <p class="error" role="alert">{ e }</p> }
            <button type="submit" class="primary" onclick={submit(false)} disabled={*busy || (exists && !*replace)}>
                { if *busy { "Saving…" } else { "Save secret" } }
            </button>
            <button type="button" class="btn ghost wide" onclick={submit(true)} disabled={*busy}>{ "Decline" }</button>
            <p class="hint muted">{ "The value is encrypted immediately and never shown to the agent's page or logs. Only the final name is reported back." }</p>
        </form>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(orig: Option<&str>, key: &str) -> Entry {
        Entry {
            orig: orig.map(|o| (o.to_owned(), None)),
            key: key.into(),
            description: None,
            value: None,
            deleted: false,
        }
    }

    #[test]
    fn ops_describe_the_diff() {
        let mut renamed = e(Some("prod/A"), "production/A");
        renamed.value = Some("v".into());
        let mut deleted = e(Some("B"), "B");
        deleted.deleted = true;
        let mut new = e(None, "C");
        new.value = Some("c".into());
        let mut described = e(Some("D"), "D");
        described.description = Some("d".into());
        let ops = ops_for(&[e(Some("same"), "same"), renamed, deleted, new, described]);
        assert_eq!(
            ops,
            vec![
                EditOp::Rename {
                    from: "prod/A".into(),
                    to: "production/A".into()
                },
                EditOp::Put {
                    key: "production/A".into(),
                    value: Some("v".into()),
                    description: Some(String::new())
                },
                EditOp::Delete { key: "B".into() },
                EditOp::Put {
                    key: "C".into(),
                    value: Some("c".into()),
                    description: None
                },
                EditOp::Put {
                    key: "D".into(),
                    value: None,
                    description: Some("d".into())
                },
            ]
        );
    }

    #[test]
    fn keys_and_folders() {
        assert_eq!(split_key("a/b/C"), ("a/b".into(), "C".into()));
        assert_eq!(join_key(" /a/b/ ", " C "), "a/b/C");
        assert_eq!(join_key("", "C"), "C");
        assert!(valid_key("a/b/C") && !valid_key("a//C") && !valid_key("a/.C"));
        assert_eq!(
            folders_of(&[e(None, "x/y/Z")], &["w".into()]),
            vec!["w", "x", "x/y"]
        );
    }
}
