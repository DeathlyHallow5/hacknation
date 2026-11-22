//! Simple, explainable classification on top of httpx output (PROJECT.md §6.2):
//! CMS from detected technologies, admin panels and staging/test environments from
//! hostname, title and URL. Path probing (/admin, /login) belongs to custom signatures (§6.3).

const CMS: &[&str] = &[
    "WordPress", "Joomla", "Drupal", "TYPO3", "Magento", "PrestaShop", "Shopware", "OpenCart",
    "Ghost", "Concrete CMS", "Umbraco", "Liferay", "1C-Bitrix", "Craft CMS", "Strapi",
    "MediaWiki", "DokuWiki", "Moodle", "WooCommerce", "Wix", "Squarespace",
];

const ADMIN_WORDS: &[&str] = &[
    "admin", "administrator", "login", "log in", "sign in", "logowanie", "zaloguj", "dashboard",
    "phpmyadmin", "wp-login", "webmin", "cpanel", "plesk", "grafana", "jenkins", "kibana",
    "portainer", "rabbitmq management", "pgadmin", "adminer", "router", "management console",
];

const STAGING_TOKENS: &[&str] = &[
    "staging", "stage", "stg", "test", "testing", "dev", "develop", "uat", "preprod", "qa",
    "sandbox", "demo", "beta",
];

/// CMS name from httpx `tech` entries like "WordPress:6.6".
pub fn cms(tech: &[String]) -> Option<String> {
    tech.iter().find_map(|t| {
        let name = t.split(':').next().unwrap_or(t);
        CMS.iter().any(|c| c.eq_ignore_ascii_case(name)).then(|| t.clone())
    })
}

pub fn is_admin(url: &str, title: Option<&str>) -> bool {
    let hay = format!("{} {}", url.to_lowercase(), title.unwrap_or("").to_lowercase());
    ADMIN_WORDS.iter().any(|w| hay.contains(w))
}

/// Token match on hostname labels (so "devices.example.com" is not "dev"), plus title hints.
pub fn is_staging(host: &str, title: Option<&str>) -> bool {
    let host = host.to_lowercase();
    let by_host = host
        .split(['.', '-', '_'])
        .any(|tok| STAGING_TOKENS.contains(&tok));
    let title = title.unwrap_or("").to_lowercase();
    by_host || ["staging", "test environment", "środowisko testowe", "development server"]
        .iter()
        .any(|w| title.contains(w))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cms() {
        let tech = vec!["Nginx".to_string(), "WordPress:6.6".to_string()];
        assert_eq!(cms(&tech).as_deref(), Some("WordPress:6.6"));
        assert_eq!(cms(&["Apache HTTP Server:2.4".to_string()]), None);
    }

    #[test]
    fn admin_and_staging() {
        assert!(is_admin("http://10.0.0.1/", Some("phpMyAdmin")));
        assert!(!is_admin("http://10.0.0.1/", Some("It works!")));
        assert!(is_staging("app-staging.example.com", None));
        assert!(is_staging("dev.example.com", None));
        assert!(!is_staging("devices.example.com", None));
    }
}

/// Response headers kept (encrypted) for header signatures — "ciekawe nagłówki" — minus what
/// may carry credentials: cookies are stored apart without values (`HttpxRecord::cookies`),
/// and headers whose name suggests a secret keep their name with the value redacted.
pub fn stored_headers(header: &std::collections::BTreeMap<String, serde_json::Value>) -> std::collections::BTreeMap<String, serde_json::Value> {
    const SECRET: &[&str] = &["authorization", "cookie", "token", "secret", "password", "passwd", "session", "key", "auth", "csrf", "signature"];
    header
        .iter()
        .filter(|(k, _)| k.as_str() != "set_cookie" && k.len() <= 64)
        .take(64)
        .map(|(k, v)| {
            let name = k.to_lowercase();
            let value = if SECRET.iter().any(|s| name.contains(s)) {
                serde_json::Value::String("[redacted]".into())
            } else {
                match v {
                    serde_json::Value::String(s) => serde_json::Value::String(s.chars().take(512).collect()),
                    other => serde_json::Value::String(other.to_string().chars().take(512).collect()),
                }
            };
            (k.clone(), value)
        })
        .collect()
}

/// First `max` bytes of a page body, cut on a character boundary.
pub fn clip_body(body: &str, max: usize) -> &str {
    if body.len() <= max {
        return body;
    }
    let mut end = max;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

#[cfg(test)]
mod stored_header_tests {
    #[test]
    fn interesting_headers_kept_secrets_redacted() {
        let h: std::collections::BTreeMap<String, serde_json::Value> = [
            ("x_powered_by", "PHP/8.1.2"), ("server", "nginx"), ("x_api_key", "abc123"),
            ("set_cookie", "SESSION=xyz"), ("x_csrf_token", "t0k3n"), ("x_generator", "Drupal 10"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.into())))
        .collect();
        let s = super::stored_headers(&h);
        assert_eq!(s["x_powered_by"], "PHP/8.1.2");
        assert_eq!(s["x_generator"], "Drupal 10");
        assert_eq!(s["x_api_key"], "[redacted]");
        assert_eq!(s["x_csrf_token"], "[redacted]");
        assert!(!s.contains_key("set_cookie"));
        assert_eq!(super::clip_body("zażółć", 3), "za");
    }
}
