//! Module 3 — scan core (PROJECT.md §4, §6).
//! We orchestrate proven CLI scanners as subprocesses and normalize their JSON output,
//! instead of reimplementing them. Binaries live in `ASI_TOOLS_DIR` (installed by
//! `tools/install_tools.py`, SHA-256 verified) or on PATH (nmap).

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// Port/service discovery and `-sV` version detection.
    Nmap,
    /// Fast SYN/CONNECT port discovery for large ranges.
    Naabu,
    /// HTTP/HTTPS fingerprint: title, status, headers, TLS, tech.
    Httpx,
    /// TLS certificate details.
    Tlsx,
    /// Signature engine — info/tech templates only, never exploits (§6.3).
    Nuclei,
}

impl Tool {
    pub const ALL: [Tool; 5] = [Tool::Nmap, Tool::Naabu, Tool::Httpx, Tool::Tlsx, Tool::Nuclei];

    pub fn binary(self) -> &'static str {
        match self {
            Tool::Nmap => "nmap",
            Tool::Naabu => "naabu",
            // Installed as pd-httpx to avoid clashing with the Python httpx CLI.
            Tool::Httpx => "pd-httpx",
            Tool::Tlsx => "tlsx",
            Tool::Nuclei => "nuclei",
        }
    }

    pub fn resolve(self, tools_dir: &str) -> Option<PathBuf> {
        let local = Path::new(tools_dir).join(self.binary());
        if local.is_file() {
            return Some(local);
        }
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|p| p.join(self.binary()))
                .find(|p| p.is_file())
        })
    }
}

/// Run a tool with a hard timeout and return stdout. The child is killed on timeout
/// so a stuck scanner cannot outlive its scan window (§3.2).
pub async fn run(tools_dir: &str, tool: Tool, args: &[&str], timeout: Duration) -> Result<String> {
    let bin = tool
        .resolve(tools_dir)
        .with_context(|| format!("{} is not installed", tool.binary()))?;
    let child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .with_context(|| format!("{} timed out after {timeout:?}", tool.binary()))??;
    if !output.status.success() {
        bail!(
            "{} exited with {}: {}",
            tool.binary(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// TODO(A): pipeline per batch — preflight -> naabu/nmap -> httpx/tlsx -> signatures,
// with rate limit (`rate_limit_pps`), batching and window checkpoints (§3.2, §6).
