//! Parsers that turn scanner output (nmap XML, naabu/httpx JSON lines) into plain structs.
//! Fixtures in `core/fixtures/` are real output captured from the compose `lab` profile.

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn xml(text: &str) -> Result<roxmltree::Document<'_>> {
    // nmap emits <!DOCTYPE nmaprun>, which roxmltree rejects unless DTDs are allowed.
    let opts = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    Ok(roxmltree::Document::parse_with_options(text, opts)?)
}

fn child<'a, 'i>(node: roxmltree::Node<'a, 'i>, tag: &str) -> Option<roxmltree::Node<'a, 'i>> {
    node.children().find(|c| c.has_tag_name(tag))
}

fn host_ip(host: roxmltree::Node) -> Option<String> {
    host.children()
        .filter(|c| c.has_tag_name("address"))
        .find(|a| matches!(a.attribute("addrtype"), Some("ipv4" | "ipv6")))
        .and_then(|a| a.attribute("addr"))
        .map(str::to_string)
}

/// Name the user supplied for this host (domain targets), if any.
fn user_hostname(host: roxmltree::Node) -> Option<String> {
    host.descendants()
        .find(|c| c.has_tag_name("hostname") && c.attribute("type") == Some("user"))
        .and_then(|h| h.attribute("name"))
        .map(str::to_string)
}

/// Alive hosts from an `nmap -sn -oX -` pre-flight: ip -> user hostname.
pub fn nmap_alive(text: &str) -> Result<BTreeMap<String, Option<String>>> {
    let doc = xml(text)?;
    let mut out = BTreeMap::new();
    for host in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let up = child(host, "status").and_then(|s| s.attribute("state")) == Some("up");
        if let (true, Some(ip)) = (up, host_ip(host)) {
            out.insert(ip, user_hostname(host));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, PartialEq)]
pub struct NmapService {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub name: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extrainfo: Option<String>,
    pub cpe: Vec<String>,
    /// nmap `conf` (0..=10) scaled to 0..=1. 1.0 = probed match, 0.3 = guessed from port table.
    pub confidence: f32,
}

/// Open services from `nmap -sV -oX -`.
pub fn nmap_services(text: &str) -> Result<Vec<NmapService>> {
    let doc = xml(text)?;
    let mut out = Vec::new();
    for host in doc.descendants().filter(|n| n.has_tag_name("host")) {
        let Some(ip) = host_ip(host) else { continue };
        for port in host.descendants().filter(|n| n.has_tag_name("port")) {
            if child(port, "state").and_then(|s| s.attribute("state")) != Some("open") {
                continue;
            }
            let Some(portid) = port.attribute("portid").and_then(|p| p.parse().ok()) else { continue };
            let svc = child(port, "service");
            let attr = |k: &str| svc.and_then(|s| s.attribute(k)).map(str::to_string);
            out.push(NmapService {
                ip: ip.clone(),
                port: portid,
                protocol: port.attribute("protocol").unwrap_or("tcp").to_string(),
                name: attr("name"),
                product: attr("product"),
                version: attr("version"),
                extrainfo: attr("extrainfo"),
                cpe: svc
                    .map(|s| s.children().filter(|c| c.has_tag_name("cpe")).filter_map(|c| c.text()).map(str::to_string).collect())
                    .unwrap_or_default(),
                confidence: attr("conf").and_then(|c| c.parse::<f32>().ok()).map(|c| c / 10.0).unwrap_or(0.0),
            });
        }
    }
    Ok(out)
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct HostPorts {
    pub hostname: Option<String>,
    pub ports: BTreeSet<u16>,
}

#[derive(Deserialize)]
struct NaabuLine {
    ip: Option<String>,
    host: Option<String>,
    port: u16,
}

/// Open TCP ports from naabu `-json`. naabu repeats lines across retries; we dedup.
pub fn naabu(text: &str) -> BTreeMap<String, HostPorts> {
    let mut out: BTreeMap<String, HostPorts> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(rec) = serde_json::from_str::<NaabuLine>(line) else { continue };
        let Some(ip) = rec.ip.clone().or_else(|| rec.host.clone()) else { continue };
        let entry = out.entry(ip.clone()).or_default();
        entry.ports.insert(rec.port);
        if entry.hostname.is_none() {
            entry.hostname = rec.host.filter(|h| *h != ip);
        }
    }
    out
}

/// One httpx `-json` record. Unknown fields are ignored; missing ones default.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct HttpxRecord {
    pub url: String,
    pub input: String,
    pub host: String,
    pub host_ip: Option<String>,
    pub port: String,
    pub title: Option<String>,
    pub webserver: Option<String>,
    pub status_code: Option<i32>,
    pub tech: Vec<String>,
    pub header: BTreeMap<String, Value>,
    pub tls: Option<Value>,
    pub favicon: Option<String>,
    pub location: Option<String>,
    pub final_url: Option<String>,
    pub chain: Vec<Value>,
    pub failed: bool,
}

impl HttpxRecord {
    pub fn ip(&self) -> &str {
        self.host_ip.as_deref().unwrap_or(&self.host)
    }

    pub fn port_num(&self) -> Option<u16> {
        self.port.parse().ok()
    }

    /// Raw `Set-Cookie` values (httpx lowercases and underscores header names).
    pub fn cookies(&self) -> Vec<String> {
        let values = match self.header.get("set_cookie") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => Vec::new(),
        };
        values.iter().filter_map(|value| {
            let mut fields = value.split(';');
            let (name, _) = fields.next()?.split_once('=')?;
            let name = name.trim();
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)) { return None; }
            let mut safe = format!("{name}=");
            for attr in fields.map(str::trim) {
                if ["secure", "httponly", "samesite=strict", "samesite=lax", "samesite=none"].iter().any(|s| attr.eq_ignore_ascii_case(s)) {
                    safe.push_str("; "); safe.push_str(attr);
                }
            }
            Some(safe)
        }).collect()
    }

    /// Redirect hops: chain locations, then the top-level location / final URL.
    pub fn redirects(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .chain
            .iter()
            .filter_map(|hop| hop.get("location").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        for extra in [&self.location, &self.final_url].into_iter().flatten() {
            if !extra.is_empty() && !out.contains(extra) {
                out.push(extra.clone());
            }
        }
        out
    }
}

/// Parse httpx JSON lines, keeping the raw line as evidence.
pub fn httpx(text: &str) -> Vec<(HttpxRecord, String)> {
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<HttpxRecord>(l).ok().map(|r| (r, l.to_string())))
        .filter(|(r, _)| !r.failed)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_alive() {
        let alive = nmap_alive(include_str!("../fixtures/nmap_sn.xml")).unwrap();
        assert_eq!(alive.len(), 4);
        assert!(alive.contains_key("172.30.0.10"));
    }

    #[test]
    fn services_only_open_with_confidence() {
        let s = nmap_services(include_str!("../fixtures/nmap_sv.xml")).unwrap();
        assert_eq!(s.len(), 3, "closed ports must be dropped: {s:?}");
        let nginx = s.iter().find(|x| x.ip == "172.30.0.10").unwrap();
        assert_eq!((nginx.port, nginx.product.as_deref()), (80, Some("nginx")));
        assert_eq!(nginx.version.as_deref(), Some("1.27.5"));
        assert_eq!(nginx.confidence, 1.0);
        assert_eq!(nginx.cpe, vec!["cpe:/a:igor_sysoev:nginx:1.27.5"]);
    }

    #[test]
    fn naabu_dedups_retries() {
        let n = naabu(include_str!("../fixtures/naabu.jsonl"));
        assert_eq!(n.len(), 3);
        assert_eq!(n["172.30.0.2"].ports, BTreeSet::from([8000]));
    }

    #[test]
    fn cookie_evidence_omits_secret_values() {
        let r: HttpxRecord = serde_json::from_value(serde_json::json!({"header": {
            "set_cookie": ["session=SECRET; Path=/SECRET; Secure; HttpOnly; SameSite=Lax"]
        }})).unwrap();
        assert_eq!(r.cookies(), ["session=; Secure; HttpOnly; SameSite=Lax"]);
    }

    #[test]
    fn httpx_fields() {
        let h = httpx(include_str!("../fixtures/httpx.jsonl"));
        assert_eq!(h.len(), 3);
        let apache = h.iter().map(|(r, _)| r).find(|r| r.ip() == "172.30.0.11").unwrap();
        assert_eq!(apache.title.as_deref(), Some("It works! Apache httpd"));
        assert_eq!(apache.status_code, Some(200));
        assert_eq!(apache.port_num(), Some(80));
        assert!(apache.tech.iter().any(|t| t.starts_with("Apache HTTP Server")));
        assert_eq!(apache.header["server"], "Apache/2.4.71 (Unix)");
    }
}
