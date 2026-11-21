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
