//! Secrets tree: keys split on `/` into folders and drawn like `tree(1)`.
//! Top-level entries have no connectors; lines only appear inside folders.
//! Used read-only (unlock page) and interactively (editor, request view).

use agentpass_protocol::SecretSummary;
use yew::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Status {
    #[default]
    Normal,
    New,
    Changed,
    Deleted,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub key: String,
    pub description: Option<String>,
    pub status: Status,
}

impl From<&SecretSummary> for Item {
    fn from(s: &SecretSummary) -> Self {
        Item {
            key: s.key.clone(),
            description: s.description.clone(),
            status: Status::Normal,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    /// Box-drawing prefix, e.g. `│   ├── `.
    pub prefix: String,
    /// Folder name (with trailing `/`) or secret name.
    pub label: String,
    pub folder: bool,
    /// Full key, or folder path without trailing `/`.
    pub path: String,
    pub description: Option<String>,
    pub status: Status,
}

#[derive(Default)]
struct Node {
    folders: Vec<(String, Node)>,
    secrets: Vec<(String, Item)>,
}

impl Node {
    fn folder(&mut self, name: &str) -> &mut Node {
        let i = match self.folders.iter().position(|(n, _)| n == name) {
            Some(i) => i,
            None => {
                self.folders.push((name.to_owned(), Node::default()));
                self.folders.len() - 1
            }
        };
        &mut self.folders[i].1
    }

    fn sort(&mut self) {
        self.folders.sort_by(|a, b| a.0.cmp(&b.0));
        self.secrets.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, f) in &mut self.folders {
            f.sort();
        }
    }

    fn lines(&self, indent: &str, base: &str, root: bool, out: &mut Vec<Line>) {
        let total = self.folders.len() + self.secrets.len();
        let connector = |i: usize| match (root, i == total) {
            (true, _) => String::new(),
            (false, true) => format!("{indent}└── "),
            (false, false) => format!("{indent}├── "),
        };
        let child_indent = |i: usize| match (root, i == total) {
            (true, _) => String::new(),
            (false, true) => format!("{indent}    "),
            (false, false) => format!("{indent}│   "),
        };
        let mut i = 0;
        for (name, node) in &self.folders {
            i += 1;
            let path = if base.is_empty() {
                name.clone()
            } else {
                format!("{base}/{name}")
            };
            out.push(Line {
                prefix: connector(i),
                label: format!("{name}/"),
                folder: true,
                path: path.clone(),
                description: None,
                status: Status::Normal,
            });
            node.lines(&child_indent(i), &path, false, out);
        }
        for (name, item) in &self.secrets {
            i += 1;
            out.push(Line {
                prefix: connector(i),
                label: name.clone(),
                folder: false,
                path: item.key.clone(),
                description: item.description.clone(),
                status: item.status,
            });
        }
    }
}

/// Tree lines for `items` plus `extra_folders` (folders without secrets).
pub fn build_items(items: &[Item], extra_folders: &[String]) -> Vec<Line> {
    let mut root = Node::default();
    for f in extra_folders {
        let mut node = &mut root;
        for part in f.split('/').filter(|p| !p.is_empty()) {
            node = node.folder(part);
        }
    }
    for item in items {
        let parts: Vec<&str> = item.key.split('/').collect();
        let (leaf, dirs) = parts.split_last().expect("split yields one part");
        let mut node = &mut root;
        for d in dirs {
            node = node.folder(d);
        }
        node.secrets.push(((*leaf).to_owned(), item.clone()));
    }
    root.sort();
    let mut out = Vec::new();
    root.lines("", "", true, &mut out);
    out
}

/// Tree lines for a vault's secrets, plus the number of folders.
#[cfg(test)]
pub fn build(secrets: &[SecretSummary]) -> (Vec<Line>, usize) {
    let items: Vec<Item> = secrets.iter().map(Item::from).collect();
    let lines = build_items(&items, &[]);
    let folders = lines.iter().filter(|l| l.folder).count();
    (lines, folders)
}

/// What was clicked in an interactive tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Clicked {
    Secret(String),
    Folder(String),
}

#[derive(Properties, PartialEq)]
pub struct TreeViewProps {
    pub items: Vec<Item>,
    #[prop_or_default]
    pub extra_folders: Vec<String>,
    /// Path of the highlighted line.
    #[prop_or_default]
    pub selected: Option<String>,
    /// Makes lines clickable.
    #[prop_or_default]
    pub on_click: Option<Callback<Clicked>>,
    #[prop_or_default]
    pub summary: bool,
}

#[function_component(TreeView)]
pub fn tree_view(props: &TreeViewProps) -> Html {
    let lines = build_items(&props.items, &props.extra_folders);
    let folders = lines.iter().filter(|l| l.folder).count();
    let n = props.items.len();
    html! {
        <div class={classes!("tree", props.on_click.is_some().then_some("interactive"))}>
            if lines.is_empty() {
                <div class="muted">{ "(no secrets yet)" }</div>
            }
            { for lines.iter().map(|l| {
                let selected = props.selected.as_deref() == Some(l.path.as_str()) && !l.path.is_empty();
                let onclick = props.on_click.clone().map(|cb| {
                    let clicked = if l.folder { Clicked::Folder(l.path.clone()) } else { Clicked::Secret(l.path.clone()) };
                    Callback::from(move |_: MouseEvent| cb.emit(clicked.clone()))
                });
                let marker = match l.status {
                    Status::Normal => None,
                    Status::New => Some(("mark-new", " +")),
                    Status::Changed => Some(("mark-changed", " ~")),
                    Status::Deleted => Some(("mark-deleted", " (delete)")),
                };
                html! {
                    <div class={classes!("tree-line", l.folder.then_some("folder"), selected.then_some("selected"), (l.status == Status::Deleted).then_some("deleted"))}
                        {onclick} role={props.on_click.is_some().then_some("button")}
                        tabindex={props.on_click.is_some().then_some("0")}>
                        <span class="tree-prefix">{ &l.prefix }</span>
                        <span class="tree-label">{ &l.label }</span>
                        if let Some((class, text)) = marker { <span class={class}>{ text }</span> }
                        if let Some(d) = &l.description {
                            <span class="tree-desc">{ format!("  # {d}") }</span>
                        }
                    </div>
                }
            }) }
            if props.summary {
                <div class="tree-summary muted">{ format!(
                    "{n} secret{}, {folders} folder{}",
                    if n == 1 { "" } else { "s" },
                    if folders == 1 { "" } else { "s" }
                ) }</div>
            }
        </div>
    }
}

#[derive(Properties, PartialEq)]
pub struct TreeProps {
    pub secrets: Vec<SecretSummary>,
}

/// Read-only tree of a vault's secrets.
#[function_component(SecretsTree)]
pub fn secrets_tree(props: &TreeProps) -> Html {
    let items: Vec<Item> = props.secrets.iter().map(Item::from).collect();
    html! { <TreeView {items} summary=true /> }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(key: &str, d: Option<&str>) -> SecretSummary {
        SecretSummary {
            key: key.into(),
            description: d.map(Into::into),
        }
    }

    #[test]
    fn draws_nested_folders_like_tree() {
        let (lines, folders) = build(&[
            s("GITHUB_TOKEN", Some("CI")),
            s("production/DB_PASSWORD", None),
            s("production/aws/KEY", None),
            s("testing/DB_PASSWORD", None),
        ]);
        let text: Vec<String> = lines
            .iter()
            .map(|l| format!("{}{}", l.prefix, l.label))
            .collect();
        assert_eq!(
            text,
            vec![
                "production/",
                "├── aws/",
                "│   └── KEY",
                "└── DB_PASSWORD",
                "testing/",
                "└── DB_PASSWORD",
                "GITHUB_TOKEN",
            ]
        );
        assert_eq!(folders, 3);
        assert_eq!(lines[1].path, "production/aws");
        assert_eq!(lines[2].path, "production/aws/KEY");
        assert_eq!(lines[6].description.as_deref(), Some("CI"));
    }

    #[test]
    fn empty_folders_are_shown() {
        let lines = build_items(&[], &["staging/eu".into()]);
        let paths: Vec<&str> = lines.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(paths, vec!["staging", "staging/eu"]);
    }

    #[test]
    fn empty_vault() {
        assert_eq!(build(&[]), (vec![], 0));
    }
}
