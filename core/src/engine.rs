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

/// Copy of naabu with the `cap_net_raw` file capability (core/Dockerfile), for SYN scans.
const NAABU_RAW: &str = "naabu-raw";
/// CAP_NET_RAW bit in /proc/<pid>/status capability masks.
const CAP_NET_RAW: u32 = 13;

/// The SYN-capable naabu, if this process can actually use it: the binary is there, the
/// container grants NET_RAW (else exec fails with EPERM) and no-new-privileges is off
/// (else the file capability is ignored and naabu silently falls back to CONNECT).
pub fn raw_naabu(tools_dir: &str) -> std::result::Result<PathBuf, String> {
    let bin = Path::new(tools_dir).join(NAABU_RAW);
    if !bin.is_file() {
        return Err(format!("{} not found", bin.display()));
    }
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| format!("/proc/self/status: {e}"))?;
    raw_capable(&status)?;
    Ok(bin)
}

fn raw_capable(status: &str) -> std::result::Result<(), String> {
    let field = |name: &str| status.lines().find_map(|l| l.strip_prefix(name)).map(str::trim);
    let bounding = field("CapBnd:").and_then(|v| u64::from_str_radix(v, 16).ok()).ok_or("no CapBnd")?;
    if bounding & (1 << CAP_NET_RAW) == 0 {
        return Err("the container does not grant NET_RAW (cap_add: [NET_RAW])".into());
    }
    if field("NoNewPrivs:") == Some("1") {
        return Err("no-new-privileges is on, file capabilities are ignored".into());
    }
    Ok(())
}

/// Run a binary that is not one of the [`Tool`]s (e.g. [`raw_naabu`]) the same way as [`run`].
pub async fn run_bin(bin: &Path, name: &str, args: &[&str], timeout: Duration) -> Result<String> {
    run_path(bin, name, args, timeout, MAX_STDOUT).await
}

/// Max stdout kept from one tool invocation. Hostile banners or a runaway tool must not
/// exhaust memory: past this the tool is killed and the batch fails (F-10).
pub const MAX_STDOUT: u64 = 64 * 1024 * 1024;


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
    let stop_file = std::env::var_os("ASI_STOP_FILE").map(PathBuf::from);
    let stopped = || stop_file.as_ref().is_some_and(|p| p.try_exists().unwrap_or(true));
    anyhow::ensure!(!stopped(), "scanner stopped by administrator");
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
        let mut sink = tokio::io::sink();
        let drain_err = tokio::io::copy(&mut stderr, &mut sink);
        let (out, _) = tokio::try_join!(read_out, async { Ok::<_, anyhow::Error>(drain_err.await?) })?;
        let status = child.wait().await?;
        Ok::<_, anyhow::Error>((status, out))
    };
    let stop = async {
        if stop_file.is_none() { std::future::pending::<()>().await; }
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if stopped() { break; }
        }
    };
    let (status, out) = tokio::select! {
        result = tokio::time::timeout(timeout, work) => result.with_context(|| format!("{name} timed out"))??,
        () = stop => bail!("scanner stopped by administrator"),
    };
    if !status.success() {
        bail!("{name} exited with {status}");
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

    #[test]
    fn raw_scan_needs_net_raw_and_privs_allowed() {
        // cap_drop ALL + cap_add NET_RAW (bit 13 = 0x2000), no-new-privileges off.
        assert!(raw_capable("CapBnd:\t0000000000002000\nNoNewPrivs:\t0\n").is_ok());
        assert!(raw_capable("CapBnd:\t0000000000000000\nNoNewPrivs:\t0\n").unwrap_err().contains("NET_RAW"));
        assert!(raw_capable("CapBnd:\t0000000000002000\nNoNewPrivs:\t1\n").unwrap_err().contains("no-new-privileges"));
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
        assert!(!err.to_string().contains("boom"), "{err}");
    }
}
