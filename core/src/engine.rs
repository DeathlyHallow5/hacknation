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

/// Max stdout kept from one tool invocation. Hostile banners or a runaway tool must not
/// exhaust memory: past this the tool is killed and the batch fails (F-10).
pub const MAX_STDOUT: u64 = 64 * 1024 * 1024;
/// Stderr is only used for error messages.
const MAX_STDERR: u64 = 16 * 1024;

/// Run a tool with a hard timeout and return stdout. The child is killed on timeout
/// so a stuck scanner cannot outlive its scan window (§3.2).
pub async fn run(tools_dir: &str, tool: Tool, args: &[&str], timeout: Duration) -> Result<String> {
    let bin = tool
        .resolve(tools_dir)
        .with_context(|| format!("{} is not installed", tool.binary()))?;
    run_path(&bin, tool.binary(), args, timeout, MAX_STDOUT).await
}

async fn run_path(bin: &Path, name: &str, args: &[&str], timeout: Duration, max_stdout: u64) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdout = child.stdout.take().context("stdout pipe")?;
    let mut stderr = child.stderr.take().context("stderr pipe")?;

    let work = async {
        let read_out = async {
            let mut buf = Vec::new();
            (&mut stdout).take(max_stdout + 1).read_to_end(&mut buf).await?;
            if buf.len() as u64 > max_stdout {
                bail!("{name} output exceeded {max_stdout} bytes, killed");
            }
            Ok(buf)
        };
        let read_err = async {
            let mut buf = Vec::new();
            (&mut stderr).take(MAX_STDERR).read_to_end(&mut buf).await?;
            // Drain the rest so the child never blocks on a full stderr pipe.
            tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await?;
            Ok::<_, anyhow::Error>(buf)
        };
        // try_join: an oversized stdout returns at once; dropping `child` kills it.
        let (out, err) = tokio::try_join!(read_out, read_err)?;
        let status = child.wait().await?;
        Ok::<_, anyhow::Error>((status, out, err))
    };
    let (status, out, err) = tokio::time::timeout(timeout, work)
        .await
        .with_context(|| format!("{name} timed out after {timeout:?}"))??;
    if !status.success() {
        bail!("{name} exited with {status}: {}", String::from_utf8_lossy(&err).trim());
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn endless_output_is_cut_off() {
        // T-11: a tool that prints forever is killed at the byte cap, not after OOM.
        let yes = Path::new("/usr/bin/yes");
        if !yes.is_file() {
            return;
        }
        let started = std::time::Instant::now();
        let err = run_path(yes, "yes", &[], Duration::from_secs(10), 1 << 20).await.unwrap_err();
        assert!(err.to_string().contains("exceeded"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn normal_output_and_exit_code() {
        let sh = Path::new("/bin/sh");
        if !sh.is_file() {
            return;
        }
        let out = run_path(sh, "sh", &["-c", "echo ok"], Duration::from_secs(5), 1024).await.unwrap();
        assert_eq!(out, "ok\n");
        let err = run_path(sh, "sh", &["-c", "echo boom >&2; exit 3"], Duration::from_secs(5), 1024).await.unwrap_err();
        assert!(err.to_string().contains("boom"), "{err}");
    }
}
