//! The agentpass agent skill (`skills/agentpass/SKILL.md`) and an installer
//! that copies it into the skill directories of coding agents.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, MultiSelect, Select};

/// The skill, embedded at build time.
pub const SKILL_MD: &str = include_str!("../../../skills/agentpass/SKILL.md");
pub const SKILL_NAME: &str = "agentpass";

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Tool {
    /// Claude Code (~/.claude/skills, .claude/skills)
    Claude,
    /// OpenAI Codex (~/.agents/skills, .agents/skills); also read by Cursor,
    /// Copilot, Gemini CLI and OpenCode
    Codex,
    /// Cursor (~/.cursor/skills, .cursor/skills)
    Cursor,
    /// GitHub Copilot (~/.copilot/skills, .github/skills)
    Copilot,
    /// Gemini CLI (~/.gemini/skills, .gemini/skills)
    Gemini,
    /// OpenCode (~/.config/opencode/skills, .opencode/skills)
    Opencode,
}

pub const ALL_TOOLS: [Tool; 6] = [
    Tool::Claude,
    Tool::Codex,
    Tool::Cursor,
    Tool::Copilot,
    Tool::Gemini,
    Tool::Opencode,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// In the home directory: every project.
    Global,
    /// In the current project (git root or current directory).
    Project,
}

impl Tool {
    pub fn label(self) -> &'static str {
        match self {
            Tool::Claude => "Claude Code",
            Tool::Codex => "Codex (.agents/skills, shared by many agents)",
            Tool::Cursor => "Cursor",
            Tool::Copilot => "GitHub Copilot",
            Tool::Gemini => "Gemini CLI",
            Tool::Opencode => "OpenCode",
        }
    }

    /// Skills directory, relative to the home directory or project root.
    fn skills_dir(self, scope: Scope) -> &'static str {
        match (self, scope) {
            (Tool::Claude, _) => ".claude/skills",
            (Tool::Codex, _) => ".agents/skills",
            (Tool::Cursor, _) => ".cursor/skills",
            (Tool::Copilot, Scope::Global) => ".copilot/skills",
            (Tool::Copilot, Scope::Project) => ".github/skills",
            (Tool::Gemini, _) => ".gemini/skills",
            (Tool::Opencode, Scope::Global) => ".config/opencode/skills",
            (Tool::Opencode, Scope::Project) => ".opencode/skills",
        }
    }

    /// Whether the tool seems to be in use (its config directory exists).
    fn detected(self, home: &Path) -> bool {
        let marker = match self {
            Tool::Claude => ".claude",
            Tool::Codex => ".codex",
            Tool::Cursor => ".cursor",
            Tool::Copilot => ".copilot",
            Tool::Gemini => ".gemini",
            Tool::Opencode => ".config/opencode",
        };
        home.join(marker).exists()
    }
}

/// Nearest directory containing `.git`, else the current directory.
fn project_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    Ok(cwd
        .ancestors()
        .find(|d| d.join(".git").exists())
        .unwrap_or(&cwd)
        .to_owned())
}

fn base_dir(scope: Scope) -> Result<PathBuf> {
    match scope {
        Scope::Global => dirs::home_dir().context("cannot determine the home directory"),
        Scope::Project => project_root(),
    }
}

/// Where the skill goes for `tools`, deduplicated (several tools may share
/// a directory).
pub fn targets(tools: &[Tool], scope: Scope, base: &Path) -> Vec<(PathBuf, Vec<Tool>)> {
    let mut out: Vec<(PathBuf, Vec<Tool>)> = Vec::new();
    for &t in tools {
        let file = base
            .join(t.skills_dir(scope))
            .join(SKILL_NAME)
            .join("SKILL.md");
        match out.iter_mut().find(|(p, _)| *p == file) {
            Some((_, ts)) => ts.push(t),
            None => out.push((file, vec![t])),
        }
    }
    out
}

pub enum Outcome {
    Created,
    Updated,
    Unchanged,
}

pub fn write_skill(file: &Path) -> Result<Outcome> {
    let outcome = match std::fs::read_to_string(file) {
        Ok(existing) if existing == SKILL_MD => return Ok(Outcome::Unchanged),
        Ok(_) => Outcome::Updated,
        Err(_) => Outcome::Created,
    };
    let dir = file.parent().expect("skill file has a parent");
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::write(file, SKILL_MD).with_context(|| format!("writing {}", file.display()))?;
    Ok(outcome)
}

pub struct InitOptions {
    pub tools: Vec<Tool>,
    pub all: bool,
    pub scope: Option<Scope>,
    pub yes: bool,
}

/// `agentpass init-skill`: asks which agents and which scope (unless given
/// as flags), then installs the skill.
pub fn init(opts: InitOptions) -> Result<()> {
    let interactive = std::io::stdin().is_terminal() && std::io::stderr().is_terminal();
    let theme = ColorfulTheme::default();
    let home = dirs::home_dir().unwrap_or_default();

    let tools: Vec<Tool> = if opts.all {
        ALL_TOOLS.to_vec()
    } else if !opts.tools.is_empty() {
        opts.tools.clone()
    } else if interactive {
        let labels: Vec<String> = ALL_TOOLS
            .iter()
            .map(|t| {
                if t.detected(&home) {
                    format!("{} (detected)", t.label())
                } else {
                    t.label().to_owned()
                }
            })
            .collect();
        let defaults: Vec<bool> = ALL_TOOLS.iter().map(|t| t.detected(&home)).collect();
        let picked = MultiSelect::with_theme(&theme)
            .with_prompt("Install the agentpass skill for which coding agents? (space to toggle, enter to confirm)")
            .items(&labels)
            .defaults(&defaults)
            .interact()?;
        picked.into_iter().map(|i| ALL_TOOLS[i]).collect()
    } else {
        bail!(
            "not a terminal: pass --tool <agent> (repeatable) or --all, and --global or --project"
        );
    };
    if tools.is_empty() {
        eprintln!("Nothing selected.");
        return Ok(());
    }

    let scope = match opts.scope {
        Some(s) => s,
        None if interactive => {
            let root = project_root()?;
            let items = [
                format!("Global: for all your projects (in {})", home.display()),
                format!("This project: commit it with the repo ({})", root.display()),
            ];
            match Select::with_theme(&theme)
                .with_prompt("Where?")
                .items(&items)
                .default(0)
                .interact()?
            {
                0 => Scope::Global,
                _ => Scope::Project,
            }
        }
        None => bail!("not a terminal: pass --global or --project"),
    };

    let base = base_dir(scope)?;
    let targets = targets(&tools, scope, &base);
    eprintln!("The skill will be written to:");
    for (file, ts) in &targets {
        let names: Vec<&str> = ts.iter().map(|t| t.label()).collect();
        eprintln!("  {}  ({})", file.display(), names.join(", "));
    }
    if !opts.yes
        && interactive
        && !Confirm::with_theme(&theme)
            .with_prompt("Continue?")
            .default(true)
            .interact()?
    {
        eprintln!("Cancelled.");
        return Ok(());
    }
    for (file, _) in &targets {
        let what = match write_skill(file)? {
            Outcome::Created => "installed",
            Outcome::Updated => "updated",
            Outcome::Unchanged => "already up to date",
        };
        eprintln!("  {what}: {}", file.display());
    }
    eprintln!("Done. Restart your coding agent (or reload skills) to pick it up.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_has_valid_frontmatter() {
        let fm = SKILL_MD
            .strip_prefix("---\n")
            .and_then(|s| s.split_once("\n---\n"))
            .expect("frontmatter")
            .0;
        assert!(fm.lines().any(|l| l == "name: agentpass"));
        let desc = fm
            .lines()
            .find_map(|l| l.strip_prefix("description: "))
            .unwrap();
        assert!(desc.len() <= 1024, "description too long for the spec");
    }

    #[test]
    fn targets_are_per_scope_and_deduplicated() {
        let base = Path::new("/home/u");
        let t = targets(
            &[Tool::Copilot, Tool::Codex, Tool::Codex],
            Scope::Project,
            base,
        );
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].0, base.join(".github/skills/agentpass/SKILL.md"));
        assert_eq!(t[1].0, base.join(".agents/skills/agentpass/SKILL.md"));
        let g = targets(&[Tool::Opencode, Tool::Copilot], Scope::Global, base);
        assert_eq!(
            g[0].0,
            base.join(".config/opencode/skills/agentpass/SKILL.md")
        );
        assert_eq!(g[1].0, base.join(".copilot/skills/agentpass/SKILL.md"));
    }

    #[test]
    fn writing_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("a/agentpass/SKILL.md");
        assert!(matches!(write_skill(&f).unwrap(), Outcome::Created));
        assert!(matches!(write_skill(&f).unwrap(), Outcome::Unchanged));
        std::fs::write(&f, "old").unwrap();
        assert!(matches!(write_skill(&f).unwrap(), Outcome::Updated));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), SKILL_MD);
    }
}
