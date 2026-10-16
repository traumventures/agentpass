//! The secrets tree on the unlock page: keys split on `/` into folders and
//! drawn like `tree(1)`.

use agentpass_protocol::SecretSummary;
use yew::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    /// Box-drawing prefix, e.g. `│   ├── `.
    pub prefix: String,
    /// Folder name (with trailing `/`) or secret name.
    pub label: String,
    pub folder: bool,
    pub description: Option<String>,
}

#[derive(Default)]
struct Node {
    /// Sorted: folders first, then secrets, each alphabetically.
    folders: Vec<(String, Node)>,
    secrets: Vec<(String, Option<String>)>,
}

impl Node {
    fn insert(&mut self, path: &[&str], description: Option<String>) {
        match path {
            [] => {}
            [leaf] => self.secrets.push(((*leaf).to_owned(), description)),
            [dir, rest @ ..] => {
                let i = match self.folders.iter().position(|(n, _)| n == dir) {
                    Some(i) => i,
                    None => {
                        self.folders.push(((*dir).to_owned(), Node::default()));
                        self.folders.len() - 1
                    }
                };
                self.folders[i].1.insert(rest, description);
            }
        }
    }

    fn sort(&mut self) {
        self.folders.sort_by(|a, b| a.0.cmp(&b.0));
        self.secrets.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, f) in &mut self.folders {
            f.sort();
        }
    }

    fn count(&self) -> usize {
        self.secrets.len() + self.folders.iter().map(|(_, f)| f.count()).sum::<usize>()
    }

    /// Top-level entries (`root`) are drawn without connectors; tree lines
    /// only appear inside folders.
    fn lines(&self, indent: &str, root: bool, out: &mut Vec<Line>) {
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
            out.push(Line {
                prefix: connector(i),
                label: format!("{name}/"),
                folder: true,
                description: None,
            });
            node.lines(&child_indent(i), false, out);
        }
        for (name, description) in &self.secrets {
            i += 1;
            out.push(Line {
                prefix: connector(i),
                label: name.clone(),
                folder: false,
                description: description.clone(),
            });
        }
    }
}

/// Tree lines for `secrets`, plus the number of folders.
pub fn build(secrets: &[SecretSummary]) -> (Vec<Line>, usize) {
    let mut root = Node::default();
    for s in secrets {
        let parts: Vec<&str> = s.key.split('/').collect();
        root.insert(&parts, s.description.clone());
    }
    root.sort();
    debug_assert_eq!(root.count(), secrets.len());
    let mut out = Vec::new();
    root.lines("", true, &mut out);
    let folders = out.iter().filter(|l| l.folder).count();
    (out, folders)
}

#[derive(Properties, PartialEq)]
pub struct TreeProps {
    pub secrets: Vec<SecretSummary>,
}

#[function_component(SecretsTree)]
pub fn secrets_tree(props: &TreeProps) -> Html {
    let (lines, folders) = build(&props.secrets);
    let n = props.secrets.len();
    let summary = format!(
        "{n} secret{}, {folders} folder{}",
        if n == 1 { "" } else { "s" },
        if folders == 1 { "" } else { "s" }
    );
    html! {
        <div class="tree" aria-label="Secrets in this vault">
            if lines.is_empty() {
                <div class="muted">{ "(no secrets yet)" }</div>
            }
            { for lines.iter().map(|l| html! {
                <div class={classes!("tree-line", l.folder.then_some("folder"))}>
                    <span class="tree-prefix">{ &l.prefix }</span>
                    <span class="tree-label">{ &l.label }</span>
                    if let Some(d) = &l.description {
                        <span class="tree-desc">{ format!("  # {d}") }</span>
                    }
                </div>
            }) }
            <div class="tree-summary muted">{ summary }</div>
        </div>
    }
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
        assert_eq!(lines[6].description.as_deref(), Some("CI"));
    }

    #[test]
    fn empty_vault() {
        assert_eq!(build(&[]), (vec![], 0));
    }
}
