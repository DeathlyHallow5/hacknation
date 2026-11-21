/**
 * Catalogue of services found on a typical Polish university campus network.
 * Used by the mock to generate realistic hosts, HTTP fingerprints and findings.
 */
import type { DeviceType, TechCategory } from "@/lib/api/types";

export interface CookieTpl {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: "Strict" | "Lax" | "None" | null;
}

export interface TechTpl {
  name: string;
  category: TechCategory;
  /** "app" = the template's app version, "server" = web server version, string = fixed, null = unknown. */
  version: "app" | "server" | string | null;
  via: ("header" | "cookie" | "html" | "favicon" | "path" | "title" | "banner")[];
}

export interface WebApp {
  key: string;
  label: string;
  port: number;
  https: boolean;
  /** Adds an HTTP :80 service that redirects to the main one. */
  redirectFromHttp?: boolean;
  nmapName: string;
  product: string;
  serverVersions: string[];
  oldServerVersions?: string[];
  appVersions: string[];
  oldAppVersions?: string[];
  server: (serverVersion: string) => string;
  poweredBy?: string;
  title: string;
  headers?: [name: string, value: string, note: string | null][];
  cookies?: CookieTpl[];
  techs: TechTpl[];
  admin?: { path: string; title: string };
  env?: "staging" | "dev" | "test";
  favicon?: number;
  exposure?: string;
  iot?: boolean;
  /** HTML excerpt, "{v}" = app version. */
  body: string;
  redirectPath?: string;
  device?: DeviceType;
}

const apache = (v: string) => `Apache/${v} (Debian)`;
const nginx = (v: string) => `nginx/${v}`;

export const WEB_APPS: Record<string, WebApp> = {
  wordpress: {
    key: "wordpress",
    label: "WordPress",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "Apache httpd",
    serverVersions: ["2.4.57", "2.4.58"],
    appVersions: ["6.4.3", "6.5.2", "6.6.1"],
    oldAppVersions: ["5.8.9", "5.9.3"],
    server: apache,
    poweredBy: "PHP/8.1.27",
    title: "Wydział — strona główna",
    headers: [["Link", '<https://{host}/wp-json/>; rel="https://api.w.org/"', "Wskazuje REST API WordPressa"]],
    cookies: [{ name: "wordpress_test_cookie", secure: false, httpOnly: false, sameSite: null }],
    techs: [
      { name: "WordPress", category: "cms", version: "app", via: ["html", "path", "cookie"] },
      { name: "PHP", category: "language", version: "8.1.27", via: ["header"] },
      { name: "Apache HTTP Server", category: "web_server", version: "server", via: ["header"] },
    ],
    admin: { path: "/wp-admin/", title: "Logowanie ‹ WordPress" },
    favicon: -1416231453,
    body: '<meta name="generator" content="WordPress {v}" />',
  },
  moodle: {
    key: "moodle",
    label: "Moodle",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "Apache httpd",
    serverVersions: ["2.4.57"],
    appVersions: ["4.3.2", "4.4.1"],
    oldAppVersions: ["3.11.18"],
    server: apache,
    title: "Platforma e-learningowa: Zaloguj się na tej stronie",
    cookies: [{ name: "MoodleSession", secure: true, httpOnly: true, sameSite: "Lax" }],
    techs: [
      { name: "Moodle", category: "cms", version: "app", via: ["cookie", "html"] },
      { name: "PHP", category: "language", version: null, via: ["cookie"] },
      { name: "Apache HTTP Server", category: "web_server", version: "server", via: ["header"] },
    ],
    redirectPath: "/login/index.php",
    favicon: 1564395906,
    body: '<meta name="keywords" content="moodle, Platforma e-learningowa" />',
  },
  usos: {
    key: "usos",
    label: "USOSweb",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "Apache httpd",
    serverVersions: ["2.4.57"],
    appVersions: ["7.1.0", "7.2.1"],
    server: apache,
    title: "USOSweb: Strona główna",
    cookies: [{ name: "PHPSESSID", secure: true, httpOnly: true, sameSite: "Lax" }],
    techs: [
      { name: "USOSweb", category: "cms", version: "app", via: ["title", "html"] },
      { name: "PHP", category: "language", version: null, via: ["cookie"] },
      { name: "Apache HTTP Server", category: "web_server", version: "server", via: ["header"] },
    ],
    body: '<a href="/kontroler.php?_action=news/default">Uniwersytecki System Obsługi Studiów</a> wersja {v}',
  },
  drupal: {
    key: "drupal",
    label: "Drupal",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "nginx",
    serverVersions: ["1.24.0"],
    appVersions: ["10.1.6", "10.2.3"],
    oldAppVersions: ["7.98"],
    server: nginx,
    title: "Biblioteka Główna",
    headers: [
      ["X-Generator", "Drupal {major} (https://www.drupal.org)", "Ujawnia CMS i jego wersję główną"],
      ["X-Drupal-Cache", "HIT", null],
    ],
    techs: [
      { name: "Drupal", category: "cms", version: "app", via: ["header", "html"] },
      { name: "nginx", category: "web_server", version: "server", via: ["header"] },
    ],
    admin: { path: "/user/login", title: "Logowanie | Biblioteka Główna" },
    body: '<meta name="Generator" content="Drupal {major} (https://www.drupal.org)" />',
  },
  joomla: {
    key: "joomla",
    label: "Joomla!",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "Apache httpd",
    serverVersions: ["2.4.57"],
    oldServerVersions: ["2.4.29"],
    appVersions: ["4.4.2"],
    oldAppVersions: ["3.10.12"],
    server: (v) => `Apache/${v} (Ubuntu)`,
    title: "Koło Naukowe — Joomla!",
    techs: [
      { name: "Joomla!", category: "cms", version: "app", via: ["html", "path"] },
      { name: "Apache HTTP Server", category: "web_server", version: "server", via: ["header"] },
    ],
    admin: { path: "/administrator/", title: "Panel administracyjny Joomla!" },
    body: '<meta name="generator" content="Joomla! - Open Source Content Management" /> Powered by Joomla! {v}',
  },
  nextcloud: {
    key: "nextcloud",
    label: "Nextcloud",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "Apache httpd",
    serverVersions: ["2.4.57"],
    appVersions: ["27.1.4", "28.0.2"],
    server: apache,
    title: "Nextcloud",
    headers: [["X-Robots-Tag", "noindex, nofollow", null]],
    cookies: [
      { name: "oc_sessionPassphrase", secure: true, httpOnly: true, sameSite: "Lax" },
      { name: "__Host-nc_sameSiteCookielax", secure: true, httpOnly: true, sameSite: "Lax" },
    ],
    techs: [
      { name: "Nextcloud", category: "other", version: "app", via: ["cookie", "title"] },
      { name: "PHP", category: "language", version: null, via: ["cookie"] },
    ],
    redirectPath: "/login",
    body: '<div id="body-login" data-nc-version="{v}">',
  },
  roundcube: {
    key: "roundcube",
    label: "Roundcube",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "nginx",
    serverVersions: ["1.22.1"],
    appVersions: ["1.6.6"],
    oldAppVersions: ["1.4.13"],
    server: nginx,
    title: "Poczta uczelniana :: Witamy w Poczta uczelniana",
    cookies: [{ name: "roundcube_sessid", secure: true, httpOnly: true, sameSite: null }],
    techs: [
      { name: "Roundcube", category: "mail", version: "app", via: ["cookie", "html"] },
      { name: "nginx", category: "web_server", version: "server", via: ["header"] },
    ],
    body: '<meta name="generator" content="Roundcube Webmail {v}" />',
  },
  gitlab: {
    key: "gitlab",
    label: "GitLab",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "nginx",
    serverVersions: ["1.24.0"],
    appVersions: ["16.9.1", "17.2.0"],
    oldAppVersions: ["15.11.13"],
    server: () => "nginx",
    title: "Sign in · GitLab",
    cookies: [{ name: "_gitlab_session", secure: true, httpOnly: true, sameSite: "Lax" }],
    techs: [
      { name: "GitLab", category: "devops", version: "app", via: ["cookie", "title", "favicon"] },
      { name: "Ruby on Rails", category: "framework", version: null, via: ["header"] },
    ],
    redirectPath: "/users/sign_in",
    admin: { path: "/admin", title: "Sign in · GitLab" },
    favicon: 1278323681,
    body: '<meta content="GitLab" property="og:site_name">',
  },
  keycloak: {
    key: "keycloak",
    label: "Keycloak",
    port: 8443,
    https: true,
    nmapName: "https-alt",
    product: "Keycloak",
    serverVersions: ["22.0.5"],
    appVersions: ["22.0.5", "24.0.3"],
    server: () => "",
    title: "Welcome to Keycloak",
    cookies: [{ name: "AUTH_SESSION_ID", secure: true, httpOnly: true, sameSite: "None" }],
    techs: [{ name: "Keycloak", category: "framework", version: "app", via: ["title", "cookie"] }],
    admin: { path: "/admin/master/console/", title: "Keycloak Administration Console" },
    body: '<div class="welcome-header">Welcome to <strong>Keycloak</strong></div>',
  },
  iis: {
    key: "iis",
    label: "Microsoft IIS",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "Microsoft IIS httpd",
    serverVersions: ["10.0"],
    appVersions: ["4.0.30319"],
    server: (v) => `Microsoft-IIS/${v}`,
    poweredBy: "ASP.NET",
    title: "System kadrowo-płacowy",
    headers: [["X-AspNet-Version", "4.0.30319", "Ujawnia wersję .NET Framework"]],
    cookies: [{ name: "ASP.NET_SessionId", secure: false, httpOnly: true, sameSite: "Lax" }],
    techs: [
      { name: "Microsoft IIS", category: "web_server", version: "server", via: ["header"] },
      { name: "ASP.NET", category: "framework", version: "app", via: ["header", "cookie"] },
    ],
    body: '<form method="post" action="./Login.aspx" id="form1">',
  },
  nginx_default: {
    key: "nginx_default",
    label: "nginx (strona domyślna)",
    port: 80,
    https: false,
    nmapName: "http",
    product: "nginx",
    serverVersions: ["1.24.0"],
    oldServerVersions: ["1.18.0", "1.14.2"],
    appVersions: ["-"],
    server: nginx,
    title: "Welcome to nginx!",
    techs: [{ name: "nginx", category: "web_server", version: "server", via: ["header", "title"] }],
    body: "<h1>Welcome to nginx!</h1>",
  },
  apache_default: {
    key: "apache_default",
    label: "Apache (strona testowa)",
    port: 80,
    https: false,
    nmapName: "http",
    product: "Apache httpd",
    serverVersions: ["2.4.57"],
    oldServerVersions: ["2.2.15", "2.4.6"],
    appVersions: ["-"],
    server: (v) => (v.startsWith("2.2") || v === "2.4.6" ? `Apache/${v} (CentOS)` : `Apache/${v} (Debian)`),
    title: "Apache HTTP Server Test Page",
    techs: [{ name: "Apache HTTP Server", category: "web_server", version: "server", via: ["header", "title"] }],
    body: "<h1>Apache HTTP Server Test Page</h1>",
  },
  tomcat: {
    key: "tomcat",
    label: "Apache Tomcat",
    port: 8080,
    https: false,
    nmapName: "http-proxy",
    product: "Apache Tomcat",
    serverVersions: ["9.0.85", "10.1.18"],
    oldServerVersions: ["9.0.65", "8.5.93"],
    appVersions: ["-"],
    server: () => "",
    title: "Apache Tomcat/{sv}",
    cookies: [{ name: "JSESSIONID", secure: false, httpOnly: true, sameSite: null }],
    techs: [
      { name: "Apache Tomcat", category: "app_server", version: "server", via: ["title", "favicon"] },
      { name: "Java", category: "language", version: null, via: ["cookie"] },
    ],
    admin: { path: "/manager/html", title: "401 — Tomcat Manager Application" },
    favicon: -297069493,
    body: "<h1>Apache Tomcat/{sv}</h1> <a href=\"/manager/html\">Manager App</a>",
  },
  jenkins: {
    key: "jenkins",
    label: "Jenkins",
    port: 8080,
    https: false,
    nmapName: "http",
    product: "Jetty",
    serverVersions: ["10.0.18"],
    appVersions: ["2.440.1", "2.452.2"],
    oldAppVersions: ["2.346.3"],
    server: (v) => `Jetty(${v})`,
    title: "Sign in [Jenkins]",
    headers: [
      ["X-Jenkins", "{v}", "Ujawnia dokładną wersję Jenkinsa"],
      ["X-Hudson", "1.395", null],
    ],
    cookies: [{ name: "JSESSIONID.4e9d1c2a", secure: false, httpOnly: true, sameSite: null }],
    techs: [
      { name: "Jenkins", category: "devops", version: "app", via: ["header", "title", "favicon"] },
      { name: "Jetty", category: "app_server", version: "server", via: ["header"] },
    ],
    redirectPath: "/login?from=%2F",
    admin: { path: "/login", title: "Sign in [Jenkins]" },
    favicon: 81586312,
    body: '<div class="simple-page" role="main">Sign in to Jenkins</div>',
  },
  phpmyadmin: {
    key: "phpmyadmin",
    label: "phpMyAdmin",
    port: 80,
    https: false,
    nmapName: "http",
    product: "Apache httpd",
    serverVersions: ["2.4.57"],
    appVersions: ["5.2.1"],
    oldAppVersions: ["4.9.11"],
    server: apache,
    poweredBy: "PHP/7.4.33",
    title: "phpMyAdmin",
    cookies: [
      { name: "phpMyAdmin", secure: false, httpOnly: true, sameSite: "Strict" },
      { name: "pma_lang", secure: false, httpOnly: true, sameSite: "Strict" },
    ],
    techs: [
      { name: "phpMyAdmin", category: "admin_panel", version: "app", via: ["cookie", "title", "path"] },
      { name: "PHP", category: "language", version: "7.4.33", via: ["header"] },
    ],
    admin: { path: "/phpmyadmin/", title: "phpMyAdmin" },
    body: '<link rel="stylesheet" href="./themes/pmahomme/css/theme.css?v={v}">',
  },
  grafana: {
    key: "grafana",
    label: "Grafana",
    port: 3000,
    https: false,
    nmapName: "ppp",
    product: "Grafana",
    serverVersions: ["10.2.3"],
    appVersions: ["10.2.3", "10.4.1"],
    oldAppVersions: ["8.3.11"],
    server: () => "",
    title: "Grafana",
    cookies: [{ name: "grafana_session", secure: false, httpOnly: true, sameSite: "Lax" }],
    techs: [{ name: "Grafana", category: "devops", version: "app", via: ["title", "html", "favicon"] }],
    redirectPath: "/login",
    admin: { path: "/login", title: "Grafana" },
    favicon: 2123863676,
    body: '"buildInfo":{"version":"{v}","edition":"Open Source"}',
  },
  kibana: {
    key: "kibana",
    label: "Kibana",
    port: 5601,
    https: false,
    nmapName: "esmagent",
    product: "Kibana",
    serverVersions: ["8.11.3"],
    appVersions: ["8.11.3"],
    oldAppVersions: ["7.10.2"],
    server: () => "",
    title: "Elastic",
    headers: [["kbn-name", "kibana", "Identyfikuje Kibanę"]],
    techs: [{ name: "Kibana", category: "devops", version: "app", via: ["header", "html"] }],
    redirectPath: "/app/home",
    body: '<kbn-injected-metadata data="{&quot;version&quot;:&quot;{v}&quot;}">',
  },
  prometheus: {
    key: "prometheus",
    label: "Prometheus",
    port: 9090,
    https: false,
    nmapName: "zeus-admin",
    product: "Prometheus",
    serverVersions: ["2.49.1"],
    appVersions: ["2.49.1"],
    server: () => "",
    title: "Prometheus Time Series Collection and Processing Server",
    techs: [{ name: "Prometheus", category: "devops", version: "app", via: ["title"] }],
    exposure: "Prometheus bez uwierzytelnienia — ujawnia metryki i adresy wewnętrzne",
    redirectPath: "/graph",
    body: '<title>Prometheus Time Series Collection and Processing Server</title>',
  },
  elastic: {
    key: "elastic",
    label: "Elasticsearch",
    port: 9200,
    https: false,
    nmapName: "wap-wsp",
    product: "Elasticsearch REST API",
    serverVersions: ["7.17.18"],
    appVersions: ["7.17.18"],
    oldAppVersions: ["6.8.23"],
    server: () => "",
    title: "",
    headers: [["X-elastic-product", "Elasticsearch", "Identyfikuje Elasticsearch"]],
    techs: [{ name: "Elasticsearch", category: "database", version: "app", via: ["header", "html"] }],
    exposure: "Elasticsearch odpowiada bez uwierzytelnienia",
    body: '{ "cluster_name" : "logi-wydzial", "version" : { "number" : "{v}" }, "tagline" : "You Know, for Search" }',
  },
  minio: {
    key: "minio",
    label: "MinIO Console",
    port: 9001,
    https: false,
    nmapName: "tor-orport",
    product: "MinIO",
    serverVersions: ["RELEASE.2024-02-17"],
    appVersions: ["RELEASE.2024-02-17"],
    server: () => "MinIO Console",
    title: "MinIO Console",
    techs: [{ name: "MinIO", category: "database", version: "app", via: ["header", "title"] }],
    admin: { path: "/login", title: "MinIO Console" },
    body: '<div id="root"></div><script>window.MINIO_CONSOLE</script>',
  },
  staging_portal: {
    key: "staging_portal",
    label: "Portal (staging)",
    port: 443,
    https: true,
    redirectFromHttp: true,
    nmapName: "https",
    product: "nginx",
    serverVersions: ["1.24.0"],
    appVersions: ["10.48.4"],
    server: nginx,
    poweredBy: "PHP/8.2.15",
    title: "[STAGING] Portal rekrutacyjny",
    headers: [
      ["X-Environment", "staging", "Wskazuje środowisko testowe"],
      ["X-Debug-Token", "{token}", "Token profilera — typowy dla trybu debugowania"],
      ["X-Robots-Tag", "noindex", null],
    ],
    cookies: [
      { name: "laravel_session", secure: false, httpOnly: true, sameSite: "Lax" },
      { name: "XSRF-TOKEN", secure: false, httpOnly: false, sameSite: "Lax" },
    ],
    techs: [
      { name: "Laravel", category: "framework", version: "app", via: ["cookie"] },
      { name: "PHP", category: "language", version: "8.2.15", via: ["header"] },
      { name: "nginx", category: "web_server", version: "server", via: ["header"] },
    ],
    env: "staging",
    body: '<div class="env-banner">ŚRODOWISKO TESTOWE — dane nie są produkcyjne</div>',
  },
  dev_app: {
    key: "dev_app",
    label: "Django (tryb debug)",
    port: 8000,
    https: false,
    nmapName: "http-alt",
    product: "WSGIServer",
    serverVersions: ["0.2"],
    appVersions: ["4.2.10"],
    server: () => "WSGIServer/0.2 CPython/3.11.8",
    title: "Page not found at /",
    techs: [
      { name: "Django", category: "framework", version: "app", via: ["html", "header"] },
      { name: "Python", category: "language", version: "3.11.8", via: ["header"] },
    ],
    env: "dev",
    body: "You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.",
  },
  jupyter: {
    key: "jupyter",
    label: "Jupyter",
    port: 8888,
    https: false,
    nmapName: "sun-answerbook",
    product: "Tornado httpd",
    serverVersions: ["6.4"],
    appVersions: ["4.1.2"],
    server: (v) => `TornadoServer/${v}`,
    title: "Home Page - Select or create a notebook",
    techs: [{ name: "Jupyter", category: "devops", version: "app", via: ["title", "header"] }],
    exposure: "Serwer Jupyter dostępny w sieci — może pozwalać na wykonanie kodu",
    body: '<body class="jp-ThemedContainer" data-notebook="tree">',
  },
  /* ----------------------- devices ----------------------- */
  printer_hp: {
    key: "printer_hp",
    label: "HP LaserJet",
    port: 80,
    https: false,
    nmapName: "http",
    product: "HP-ChaiSOE",
    serverVersions: ["1.0"],
    appVersions: ["M507", "M406", "MFP E52645"],
    server: (v) => `HP HTTP Server; HP LaserJet - ${v}`,
    title: "HP LaserJet {v} — Wbudowany serwer internetowy",
    techs: [{ name: "HP Embedded Web Server", category: "iot", version: null, via: ["header", "title"] }],
    iot: true,
    device: "printer",
    body: '<div id="pgm-footer">HP LaserJet {v}</div>',
  },
  printer_ricoh: {
    key: "printer_ricoh",
    label: "RICOH",
    port: 80,
    https: false,
    nmapName: "http",
    product: "RICOH Web Image Monitor",
    serverVersions: ["2.2"],
    appVersions: ["IM C3000", "MP C3004"],
    server: () => "Web-Server/3.0",
    title: "Web Image Monitor",
    techs: [{ name: "RICOH Web Image Monitor", category: "iot", version: null, via: ["title"] }],
    iot: true,
    device: "printer",
    admin: { path: "/web/guest/pl/websys/webArch/authForm.cgi", title: "Logowanie administratora" },
    body: '<title>Web Image Monitor</title> RICOH {v}',
  },
  camera_hik: {
    key: "camera_hik",
    label: "Hikvision",
    port: 80,
    https: false,
    nmapName: "http",
    product: "Hikvision IP camera httpd",
    serverVersions: ["5.5.0"],
    appVersions: ["DS-2CD2143G2-I", "DS-2CD2043G0-I"],
    oldAppVersions: ["DS-2CD2032-I"],
    server: () => "App-webs/",
    title: "",
    techs: [{ name: "Hikvision", category: "iot", version: "app", via: ["header", "favicon"] }],
    iot: true,
    device: "camera",
    favicon: 999357577,
    admin: { path: "/doc/page/login.asp", title: "Logowanie" },
    body: '<script>window.location.href = "/doc/page/login.asp?_" + (new Date()).getTime();</script>',
  },
  camera_axis: {
    key: "camera_axis",
    label: "AXIS",
    port: 80,
    https: false,
    nmapName: "http",
    product: "AXIS network camera",
    serverVersions: ["10.12"],
    appVersions: ["P1448-LE", "M3106-L"],
    server: () => "",
    title: "AXIS",
    techs: [{ name: "AXIS Camera", category: "iot", version: "app", via: ["title"] }],
    iot: true,
    device: "camera",
    redirectPath: "/camera/index.html",
    body: '<meta name="description" content="AXIS {v} Network Camera">',
  },
  idrac: {
    key: "idrac",
    label: "Dell iDRAC",
    port: 443,
    https: true,
    nmapName: "https",
    product: "Dell iDRAC",
    serverVersions: ["7.00.00"],
    appVersions: ["iDRAC9 7.00.00.171"],
    oldAppVersions: ["iDRAC8 2.75.75.75"],
    server: () => "Apache",
    title: "iDRAC9 - Login",
    headers: [["X-Frame-Options", "SAMEORIGIN", null]],
    techs: [{ name: "Dell iDRAC", category: "admin_panel", version: "app", via: ["title"] }],
    admin: { path: "/restgui/start.html", title: "iDRAC9 - Login" },
    device: "bmc",
    body: '<title>iDRAC9 - Login</title>',
  },
  ilo: {
    key: "ilo",
    label: "HPE iLO",
    port: 443,
    https: true,
    nmapName: "https",
    product: "HPE iLO",
    serverVersions: ["2.78"],
    appVersions: ["iLO 5 2.78"],
    oldAppVersions: ["iLO 4 2.55"],
    server: () => "HPE-iLO-Server/1.0",
    title: "iLO 5",
    techs: [{ name: "HPE iLO", category: "admin_panel", version: "app", via: ["header", "title"] }],
    admin: { path: "/html/login.html", title: "iLO 5" },
    device: "bmc",
    body: '<title>iLO 5</title>',
  },
  apc_ups: {
    key: "apc_ups",
    label: "APC UPS",
    port: 80,
    https: false,
    nmapName: "http",
    product: "Allegro RomPager",
    serverVersions: ["4.01"],
    appVersions: ["NMC2 6.9.6"],
    server: (v) => `Allegro-Software-RomPager/${v}`,
    title: "APC | Log On",
    techs: [
      { name: "APC Network Management Card", category: "iot", version: "app", via: ["title"] },
      { name: "Allegro RomPager", category: "web_server", version: "server", via: ["header"] },
    ],
    iot: true,
    device: "iot",
    admin: { path: "/logon.htm", title: "APC | Log On" },
    body: '<title>APC | Log On</title>',
  },
  mikrotik: {
    key: "mikrotik",
    label: "MikroTik RouterOS",
    port: 80,
    https: false,
    nmapName: "http",
    product: "MikroTik router config httpd",
    serverVersions: ["7.13"],
    appVersions: ["7.13.5"],
    oldAppVersions: ["6.48.6"],
    server: () => "",
    title: "RouterOS router configuration page",
    techs: [{ name: "MikroTik RouterOS", category: "network", version: "app", via: ["title"] }],
    admin: { path: "/webfig/", title: "RouterOS router configuration page" },
    device: "network",
    body: "<title>RouterOS router configuration page</title>",
  },
  cisco_http: {
    key: "cisco_http",
    label: "Cisco IOS",
    port: 80,
    https: false,
    nmapName: "http",
    product: "Cisco IOS http config",
    serverVersions: ["15.2"],
    appVersions: ["15.2(7)E4"],
    server: () => "cisco-IOS",
    title: "",
    headers: [["WWW-Authenticate", 'Basic realm="level_15_access"', "Panel konfiguracji przełącznika"]],
    techs: [{ name: "Cisco IOS", category: "network", version: "app", via: ["header"] }],
    admin: { path: "/", title: "401 — level_15_access" },
    device: "network",
    body: "401 Unauthorized",
  },
  synology: {
    key: "synology",
    label: "Synology DSM",
    port: 5001,
    https: true,
    nmapName: "commplex-link",
    product: "nginx",
    serverVersions: ["1.20"],
    appVersions: ["DSM 7.2.1"],
    oldAppVersions: ["DSM 6.2.4"],
    server: () => "nginx",
    title: "Synology DiskStation",
    techs: [{ name: "Synology DSM", category: "iot", version: "app", via: ["title"] }],
    admin: { path: "/", title: "Synology DiskStation" },
    device: "storage",
    body: '<meta name="application-name" content="Synology DiskStation">',
  },
};

export interface PlainService {
  port: number;
  protocol: "tcp" | "udp";
  name: string;
  product: string | null;
  versions: string[];
  oldVersions?: string[];
  banner?: (v: string) => string;
  exposure?: string;
  tech?: { name: string; category: TechCategory };
}

export const PLAIN: Record<string, PlainService> = {
  ssh: {
    port: 22,
    protocol: "tcp",
    name: "ssh",
    product: "OpenSSH",
    versions: ["9.2p1 Debian 2+deb12u2", "8.9p1 Ubuntu 3ubuntu0.6", "9.6p1 Ubuntu 3ubuntu13"],
    oldVersions: ["7.4 (protocol 2.0)", "6.6.1p1 Ubuntu 2ubuntu2.13"],
    banner: (v) => `SSH-2.0-OpenSSH_${v.replace(/ /g, "_")}`,
  },
  rdp: { port: 3389, protocol: "tcp", name: "ms-wbt-server", product: "Microsoft Terminal Services", versions: [""] },
  msrpc: { port: 135, protocol: "tcp", name: "msrpc", product: "Microsoft Windows RPC", versions: [""] },
  netbios: { port: 139, protocol: "tcp", name: "netbios-ssn", product: "Microsoft Windows netbios-ssn", versions: [""] },
  smb: { port: 445, protocol: "tcp", name: "microsoft-ds", product: "Microsoft Windows SMB", versions: [""] },
  winrm: { port: 5985, protocol: "tcp", name: "http", product: "Microsoft HTTPAPI httpd", versions: ["2.0"] },
  mysql: {
    port: 3306,
    protocol: "tcp",
    name: "mysql",
    product: "MySQL",
    versions: ["8.0.36", "MariaDB 10.11.6"],
    oldVersions: ["5.5.62", "5.7.44"],
    tech: { name: "MySQL", category: "database" },
  },
  postgres: {
    port: 5432,
    protocol: "tcp",
    name: "postgresql",
    product: "PostgreSQL DB",
    versions: ["15.6", "16.2"],
    oldVersions: ["9.6.24"],
    tech: { name: "PostgreSQL", category: "database" },
  },
  redis: {
    port: 6379,
    protocol: "tcp",
    name: "redis",
    product: "Redis key-value store",
    versions: ["7.2.4", "6.0.16"],
    exposure: "Redis bez hasła — polecenie INFO dostępne",
    tech: { name: "Redis", category: "database" },
  },
  mongodb: {
    port: 27017,
    protocol: "tcp",
    name: "mongodb",
    product: "MongoDB",
    versions: ["6.0.13"],
    oldVersions: ["3.6.23"],
    exposure: "MongoDB dostępne z sieci kampusowej",
    tech: { name: "MongoDB", category: "database" },
  },
  mssql: { port: 1433, protocol: "tcp", name: "ms-sql-s", product: "Microsoft SQL Server 2019", versions: ["15.00.4345"] },
  ldap: { port: 389, protocol: "tcp", name: "ldap", product: "OpenLDAP", versions: ["2.5.13"] },
  ldaps: { port: 636, protocol: "tcp", name: "ldapssl", product: "OpenLDAP", versions: ["2.5.13"] },
  dns: { port: 53, protocol: "tcp", name: "domain", product: "ISC BIND", versions: ["9.18.24"], oldVersions: ["9.11.4-P2"] },
  smtp: {
    port: 25,
    protocol: "tcp",
    name: "smtp",
    product: "Postfix smtpd",
    versions: [""],
    banner: () => "220 mx.uczelnia.example ESMTP Postfix (Debian/GNU)",
  },
  submission: { port: 587, protocol: "tcp", name: "submission", product: "Postfix smtpd", versions: [""] },
  imaps: { port: 993, protocol: "tcp", name: "imaps", product: "Dovecot imapd", versions: [""] },
  ftp: {
    port: 21,
    protocol: "tcp",
    name: "ftp",
    product: "vsftpd",
    versions: ["3.0.5"],
    oldVersions: ["2.3.4"],
    banner: (v) => `220 (vsFTPd ${v})`,
  },
  telnet: {
    port: 23,
    protocol: "tcp",
    name: "telnet",
    product: "Cisco telnetd",
    versions: ["IOS 12.X"],
    exposure: "Telnet — dane logowania przesyłane otwartym tekstem",
  },
  vnc: { port: 5900, protocol: "tcp", name: "vnc", product: "RealVNC", versions: ["6.11"], exposure: "Pulpit zdalny VNC dostępny w sieci" },
  snmp: { port: 161, protocol: "udp", name: "snmp", product: "net-snmp", versions: ["5.9"] },
  ipp: { port: 631, protocol: "tcp", name: "ipp", product: "HP printer IPP", versions: [""] },
  jetdirect: { port: 9100, protocol: "tcp", name: "jetdirect", product: null, versions: [""] },
  rtsp: { port: 554, protocol: "tcp", name: "rtsp", product: "Hikvision 7513 POE IP camera rtspd", versions: [""] },
  hiksdk: { port: 8000, protocol: "tcp", name: "http-alt", product: "Hikvision SDK", versions: [""] },
  ipmi: { port: 623, protocol: "udp", name: "asf-rmcp", product: "IPMI 2.0", versions: [""] },
  winbox: { port: 8291, protocol: "tcp", name: "unknown", product: "MikroTik WinBox", versions: [""] },
  ntp: { port: 123, protocol: "udp", name: "ntp", product: "NTP", versions: ["v4"] },
};

export type BlockType =
  | "dmz_web"
  | "srv"
  | "storage"
  | "mgmt"
  | "lab"
  | "office"
  | "print"
  | "dorm"
  | "wifi"
  | "cam"
  | "empty"
  | "excluded";

export const BLOCK_DENSITY: Record<BlockType, number> = {
  dmz_web: 0.35,
  srv: 0.42,
  storage: 0.15,
  mgmt: 0.3,
  lab: 0.28,
  office: 0.22,
  print: 0.1,
  dorm: 0.12,
  wifi: 0.12,
  cam: 0.3,
  empty: 0.004,
  excluded: 0,
};

/** Layout of 10.0.0.0/16 by /24 block index (aligned runs give clean squares on the Hilbert map). */
export function blockType(block: number): BlockType {
  if (block < 8) return "dmz_web";
  if (block < 24) return "srv";
  if (block < 28) return "storage";
  if (block < 32) return "mgmt";
  if (block < 40) return "lab";
  if (block < 48) return "srv";
  if (block < 64) return "empty";
  if (block < 80) return "office";
  if (block < 84) return "print";
  if (block < 96) return "office";
  if (block < 104) return "lab";
  if (block < 112) return "office";
  if (block < 116) return "print";
  if (block < 128) return "empty";
  if (block < 160) return "dorm";
  if (block < 184) return "wifi";
  if (block < 192) return "empty";
  if (block < 200) return "print";
  if (block < 216) return "cam";
  if (block < 220) return "mgmt";
  if (block < 224) return "empty";
  if (block < 232) return "mgmt";
  if (block < 240) return "lab";
  if (block < 248) return "srv";
  if (block === 250) return "excluded";
  return "empty";
}

export const DEPARTMENTS = [
  { slug: "wydzial-informatyki", owner: "Wydział Informatyki" },
  { slug: "wydzial-fizyki", owner: "Wydział Fizyki i Informatyki Stosowanej" },
  { slug: "wydzial-gornictwa", owner: "Wydział Górnictwa i Geoinżynierii" },
  { slug: "wydzial-metali", owner: "Wydział Metali Nieżelaznych" },
  { slug: "wydzial-zarzadzania", owner: "Wydział Zarządzania" },
  { slug: "biblioteka", owner: "Biblioteka Główna" },
  { slug: "dziekanat", owner: "Dział Nauczania" },
  { slug: "it", owner: "Dział Informatyzacji" },
  { slug: "cbi", owner: "Centrum Bezpieczeństwa Informacji" },
];

export const OWNER_BY_BLOCK_TYPE: Record<BlockType, string> = {
  dmz_web: "Dział Informatyzacji",
  srv: "Dział Informatyzacji",
  storage: "Dział Informatyzacji",
  mgmt: "Sekcja Sieci i Serwerowni",
  lab: "Wydział Informatyki",
  office: "Administracja centralna",
  print: "Administracja centralna",
  dorm: "Osiedle Studenckie",
  wifi: "Sekcja Sieci i Serwerowni",
  cam: "Dział Ochrony Mienia",
  empty: "Dział Informatyzacji",
  excluded: "Sekcja Sieci i Serwerowni",
};
