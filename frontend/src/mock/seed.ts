/**
 * Deterministic seed of the mock backend: a /16 campus network with 12 480
 * responding hosts, 30 nightly scans, a latest diff (#127 -> #128), findings,
 * signatures, users/roles and an audit trail.
 */
import type {
  Availability,
  AuditEvent,
  Change,
  ChangeState,
  ChangesTimelinePoint,
  Criticality,
  DeviceType,
  Engine,
  Finding,
  Role,
  ScanProfile,
  ScanRun,
  Schedule,
  Signature,
  Target,
  User,
} from "@/lib/api/types";
import { BUILTIN_ROLES } from "@/lib/permissions";
import {
  BLOCK_DENSITY,
  DEPARTMENTS,
  OWNER_BY_BLOCK_TYPE,
  PLAIN,
  WEB_APPS,
  blockType,
  type BlockType,
} from "@/mock/catalog";
import type { HostRec, MockDB, ServiceRec } from "@/mock/db";
import { findingsForHost } from "@/mock/findings";
import { chance, int, mulberry32, pick, pickWeighted, rngFor, sample, shuffle, type Rng } from "@/mock/rng";
import { DAY, HOUR, MIN, iso, warsaw, zoned } from "@/mock/time";

export const NET_PREFIX = "10.0";
export const NET_CIDR = "10.0.0.0/16";
const RESPONDED = 12_480;
const EXTRA = 430;

export const offToIp = (off: number) => `${NET_PREFIX}.${off >> 8}.${off & 255}`;

const SERVER_PRODUCTS = new Set([
  "Apache httpd",
  "nginx",
  "Microsoft IIS httpd",
  "Jetty",
  "Tornado httpd",
  "WSGIServer",
  "Apache Tomcat",
  "HP-ChaiSOE",
  "Allegro RomPager",
]);

interface Spec {
  web?: string;
  plain?: string;
  port?: number;
  tls?: boolean;
  old?: boolean;
  appVersion?: string;
  serverVersion?: string;
  change?: ChangeState;
  certDays?: number;
}

/* ------------------------------------------------------------------ */
/* Services                                                            */
/* ------------------------------------------------------------------ */

function makeServices(off: number, specs: Spec[], firstSeen: string, lastSeen: string, rng: Rng): ServiceRec[] {
  const out: ServiceRec[] = [];
  const used = new Set<string>();
  for (const spec of specs) {
    if (spec.web) {
      const app = WEB_APPS[spec.web];
      const port = spec.port ?? app.port;
      const tls = spec.tls ?? app.https;
      const canBeOld = Boolean(app.oldAppVersions || app.oldServerVersions);
      const old = spec.old ?? (canBeOld && chance(rng, 0.16));
      const appVersion =
        spec.appVersion ?? (old && app.oldAppVersions ? pick(rng, app.oldAppVersions) : pick(rng, app.appVersions));
      const serverVersion =
        spec.serverVersion ??
        (old && !app.oldAppVersions && app.oldServerVersions ? pick(rng, app.oldServerVersions) : pick(rng, app.serverVersions));
      const key = `${port}/tcp`;
      if (used.has(key)) continue;
      used.add(key);
      const device = Boolean(app.device);
      out.push({
        id: `s-${off}-${port}`,
        port,
        protocol: "tcp",
        name: tls && port === 443 ? "https" : app.nmapName,
        product: app.product,
        version: SERVER_PRODUCTS.has(app.product) ? serverVersion : appVersion !== "-" ? appVersion : null,
        confidence: Math.round((0.86 + rng() * 0.13) * 100) / 100,
        tls,
        banner: null,
        web: app.key,
        appVersion,
        serverVersion,
        plain: null,
        old,
        redirectTo: null,
        certDays: tls
          ? spec.certDays ??
            (device ? int(rng, 200, 3000) : chance(rng, 0.04) ? -int(rng, 1, 60) : chance(rng, 0.07) ? int(rng, 3, 20) : int(rng, 25, 340))
          : null,
        certRenewedAt: null,
        change: spec.change ?? "unchanged",
        firstSeen,
        lastSeen,
        tags: [],
        notes: null,
        overrides: {},
      });
      if (app.redirectFromHttp && tls && port === 443 && !used.has("80/tcp")) {
        used.add("80/tcp");
        out.push({
          ...out[out.length - 1],
          id: `s-${off}-80`,
          port: 80,
          name: "http",
          tls: false,
          redirectTo: 443,
          certDays: null,
          change: spec.change ?? "unchanged",
          confidence: Math.round((0.9 + rng() * 0.09) * 100) / 100,
        });
      }
    } else if (spec.plain) {
      const p = PLAIN[spec.plain];
      const port = spec.port ?? p.port;
      const key = `${port}/${p.protocol}`;
      if (used.has(key)) continue;
      used.add(key);
      const old = spec.old ?? (Boolean(p.oldVersions) && chance(rng, 0.12));
      const version = spec.appVersion ?? (old && p.oldVersions ? pick(rng, p.oldVersions) : pick(rng, p.versions));
      out.push({
        id: `s-${off}-${port}${p.protocol === "udp" ? "u" : ""}`,
        port,
        protocol: p.protocol,
        name: p.name,
        product: p.product,
        version: version || null,
        confidence: Math.round((0.8 + rng() * 0.19) * 100) / 100,
        tls: p.name === "ldapssl" || p.name === "imaps",
        banner: p.banner ? p.banner(version) : null,
        web: null,
        appVersion: null,
        serverVersion: null,
        plain: spec.plain,
        old,
        redirectTo: null,
        certDays: null,
        certRenewedAt: null,
        change: spec.change ?? "unchanged",
        firstSeen,
        lastSeen,
        tags: [],
        notes: null,
        overrides: {},
      });
    }
  }
  return out.sort((a, b) => a.port - b.port);
}

/* ------------------------------------------------------------------ */
/* Random hosts per block type                                         */
/* ------------------------------------------------------------------ */

interface Profile {
  device: DeviceType;
  os: string | null;
  specs: Spec[];
  hostnames: string[];
  criticality: Criticality;
  tags: string[];
  owner: string;
}

const deptOf = (rng: Rng) => pick(rng, DEPARTMENTS);

function randomProfile(type: BlockType, off: number, rng: Rng): Profile {
  const b = off >> 8;
  const i = off & 255;
  const dept = deptOf(rng);
  const owner = type === "srv" || type === "dmz_web" ? dept.owner : OWNER_BY_BLOCK_TYPE[type];
  const linux = () => pick(rng, ["Linux 6.1 (Debian 12)", "Linux 5.15 (Ubuntu 22.04)", "Linux 6.8 (Ubuntu 24.04)"]);
  const win = () => pick(rng, ["Windows 11 23H2", "Windows 10 22H2"]);
  const p: Profile = { device: "server", os: null, specs: [], hostnames: [], criticality: "medium", tags: [], owner };

  switch (type) {
    case "dmz_web": {
      const app = pickWeighted(rng, [
        ["wordpress", 30],
        ["drupal", 10],
        ["joomla", 6],
        ["moodle", 8],
        ["nextcloud", 6],
        ["roundcube", 4],
        ["gitlab", 3],
        ["iis", 8],
        ["nginx_default", 10],
        ["apache_default", 8],
        ["keycloak", 3],
      ] as const);
      p.os = app === "iis" ? "Windows Server 2019" : linux();
      p.specs.push({ web: app });
      if (app !== "iis" && chance(rng, 0.8)) p.specs.push({ plain: "ssh" });
      p.hostnames.push(`${app === "wordpress" ? pick(rng, ["konferencja", "projekt", "kolo", "zaklad", "katedra"]) : app.replace("_default", "")}-${b}${i}.${dept.slug}.uczelnia.example`);
      p.criticality = pick(rng, ["medium", "high", "high"]);
      p.tags = ["dmz", "www"];
      break;
    }
    case "srv": {
      p.os = linux();
      if (chance(rng, 0.9)) p.specs.push({ plain: "ssh" });
      const roles = int(rng, 1, 2);
      let label = "srv";
      for (let k = 0; k < roles; k++) {
        const role = pickWeighted(rng, [
          ["tomcat", 14],
          ["jenkins", 4],
          ["grafana", 6],
          ["kibana", 3],
          ["prometheus", 3],
          ["elastic", 2],
          ["minio", 3],
          ["phpmyadmin", 4],
          ["mysql", 12],
          ["postgres", 10],
          ["redis", 3],
          ["mongodb", 2],
          ["dns", 3],
          ["ldap", 2],
          ["mail", 2],
          ["ftp", 3],
          ["windows", 9],
          ["nginx_default", 5],
        ] as const);
        if (role === "mail") p.specs.push({ plain: "smtp" }, { plain: "submission" }, { plain: "imaps" });
        else if (role === "windows") {
          p.os = "Windows Server 2022";
          p.specs = p.specs.filter((s) => s.plain !== "ssh");
          p.specs.push({ plain: "msrpc" }, { plain: "smb" }, { plain: "rdp" }, { plain: "winrm" });
          if (chance(rng, 0.3)) p.specs.push({ plain: "mssql" });
        } else if (role === "ldap") p.specs.push({ plain: "ldap" }, { plain: "ldaps" });
        else if (role in WEB_APPS) p.specs.push({ web: role });
        else p.specs.push({ plain: role });
        label = role === "windows" ? "win" : role.replace("_default", "");
      }
      p.hostnames.push(`${label}-${String(b).padStart(2, "0")}${String(i).padStart(3, "0")}.${dept.slug}.uczelnia.example`);
      p.criticality = pick(rng, ["medium", "medium", "high"]);
      p.tags = ["serwerownia"];
      break;
    }
    case "storage": {
      p.device = "storage";
      p.os = "Synology DSM";
      p.specs.push({ web: "synology" }, { plain: "ssh" }, { plain: "smb" });
      p.hostnames.push(`nas-${b}${i}.it.uczelnia.example`);
      p.criticality = "high";
      p.tags = ["backup"];
      break;
    }
    case "mgmt": {
      const kind = pickWeighted(rng, [
        ["idrac", 35],
        ["ilo", 15],
        ["switch", 22],
        ["mikrotik", 10],
        ["ups", 18],
      ] as const);
      if (kind === "idrac" || kind === "ilo") {
        p.device = "bmc";
        p.specs.push({ web: kind }, { plain: "ipmi" });
        if (chance(rng, 0.4)) p.specs.push({ plain: "ssh" });
        p.hostnames.push(`${kind}-${b}${i}.mgmt.uczelnia.example`);
        p.criticality = "high";
      } else if (kind === "switch") {
        p.device = "network";
        p.os = "Cisco IOS 15.2";
        p.specs.push({ plain: "ssh" }, { web: "cisco_http" }, { plain: "snmp" });
        if (chance(rng, 0.25)) p.specs.push({ plain: "telnet" });
        p.hostnames.push(`sw-${b}-${i}.mgmt.uczelnia.example`);
        p.criticality = "high";
      } else if (kind === "mikrotik") {
        p.device = "network";
        p.os = "RouterOS";
        p.specs.push({ web: "mikrotik" }, { plain: "winbox" }, { plain: "ssh" });
        p.hostnames.push(`rtr-${b}-${i}.mgmt.uczelnia.example`);
        p.criticality = "high";
      } else {
        p.device = "iot";
        p.specs.push({ web: "apc_ups" }, { plain: "snmp" });
        p.hostnames.push(`ups-${b}-${i}.mgmt.uczelnia.example`);
        p.criticality = "medium";
      }
      p.tags = ["zarządzanie"];
      break;
    }
    case "lab": {
      p.os = linux();
      const kind = pickWeighted(rng, [
        ["linux", 34],
        ["staging_portal", 7],
        ["dev_app", 8],
        ["jupyter", 7],
        ["tomcat", 8],
        ["nginx_default", 8],
        ["apache_default", 8],
        ["wordpress", 5],
        ["grafana", 3],
        ["windows", 12],
      ] as const);
      if (kind === "windows") {
        p.device = "workstation";
        p.os = win();
        p.specs.push({ plain: "msrpc" }, { plain: "smb" }, { plain: "rdp" });
        p.hostnames.push(`lab-pc-${b}-${i}.wydzial-informatyki.uczelnia.example`);
      } else {
        p.specs.push({ plain: "ssh" });
        if (kind !== "linux") p.specs.push({ web: kind });
        if (chance(rng, 0.12)) p.specs.push({ plain: "mysql" });
        if (chance(rng, 0.08)) p.specs.push({ plain: "postgres" });
        if (chance(rng, 0.03)) p.specs.push({ plain: "vnc" });
        const prefix = kind === "staging_portal" ? "staging" : kind === "dev_app" ? "dev" : chance(rng, 0.25) ? "test" : "lab";
        p.hostnames.push(`${prefix}-${b}-${i}.wydzial-informatyki.uczelnia.example`);
      }
      p.criticality = "low";
      p.tags = ["laboratorium"];
      break;
    }
    case "office": {
      const kind = pickWeighted(rng, [
        ["win", 72],
        ["linux", 10],
        ["printer", 5],
        ["none", 13],
      ] as const);
      p.device = kind === "printer" ? "printer" : "workstation";
      if (kind === "win") {
        p.os = win();
        p.specs.push({ plain: "msrpc" }, { plain: "netbios" }, { plain: "smb" });
        if (chance(rng, 0.4)) p.specs.push({ plain: "rdp" });
      } else if (kind === "linux") {
        p.os = linux();
        p.specs.push({ plain: "ssh" });
      } else if (kind === "printer") {
        p.specs.push({ web: "printer_hp" }, { plain: "ipp" }, { plain: "jetdirect" });
      }
      if (chance(rng, 0.6)) p.hostnames.push(`${kind === "printer" ? "drukarka" : "ws"}-${b}${String(i).padStart(3, "0")}.${dept.slug}.uczelnia.example`);
      p.criticality = "low";
      p.owner = dept.owner;
      break;
    }
    case "print": {
      p.device = "printer";
      const hp = chance(rng, 0.55);
      p.specs.push({ web: hp ? "printer_hp" : "printer_ricoh" }, { plain: "ipp" }, { plain: "jetdirect" }, { plain: "snmp" });
      if (chance(rng, 0.5)) p.specs.push({ web: hp ? "printer_hp" : "printer_ricoh", port: 443, tls: true });
      p.hostnames.push(`drukarka-${b}-${i}.${dept.slug}.uczelnia.example`);
      p.criticality = "low";
      p.tags = ["druk"];
      break;
    }
    case "dorm":
    case "wifi": {
      p.device = "workstation";
      const kind = pickWeighted(rng, [
        ["none", type === "wifi" ? 80 : 56],
        ["win", type === "wifi" ? 12 : 30],
        ["linux", 5],
        ["rogue", 3],
      ] as const);
      if (kind === "win") {
        p.os = win();
        p.specs.push({ plain: "msrpc" }, { plain: "netbios" }, { plain: "smb" });
      } else if (kind === "linux") {
        p.os = linux();
        p.specs.push({ plain: "ssh" });
      } else if (kind === "rogue") {
        p.specs.push({ web: pick(rng, ["nginx_default", "dev_app", "apache_default"]) });
      }
      if (chance(rng, 0.4)) p.hostnames.push(`dhcp-10-0-${b}-${i}.${type === "wifi" ? "wifi" : "akademiki"}.uczelnia.example`);
      p.criticality = "low";
      p.tags = [type === "wifi" ? "wifi" : "akademiki"];
      break;
    }
    case "cam": {
      p.device = "camera";
      const hik = chance(rng, 0.7);
      p.specs.push({ web: hik ? "camera_hik" : "camera_axis" }, { plain: "rtsp" });
      if (hik) p.specs.push({ plain: "hiksdk" });
      if (!hik && chance(rng, 0.4)) p.specs.push({ web: "camera_axis", port: 443, tls: true });
      p.hostnames.push(`kamera-${b}-${i}.monitoring.uczelnia.example`);
      p.criticality = "medium";
      p.tags = ["monitoring"];
      break;
    }
    default: {
      // "empty" ranges: occasional shadow-IT device.
      p.specs.push({ web: pick(rng, ["nginx_default", "dev_app", "jupyter"]) }, { plain: "ssh" });
      p.os = linux();
      p.criticality = "low";
      p.tags = ["poza-ewidencją"];
    }
  }
  return p;
}

/* ------------------------------------------------------------------ */
/* Hand-crafted hosts (match the mockup and give the demo a story)     */
/* ------------------------------------------------------------------ */

interface Special {
  ip: string;
  hostnames: string[];
  device?: DeviceType;
  os?: string;
  specs: Spec[];
  criticality: Criticality;
  tags: string[];
  owner: string;
  change?: ChangeState;
  availability?: Availability;
}

const SPECIALS: Special[] = [
  { ip: "10.0.1.5", hostnames: ["www.uczelnia.example", "uczelnia.example"], os: "Linux 6.1 (Debian 12)", specs: [{ web: "wordpress", appVersion: "6.6.1", old: false }, { plain: "ssh" }], criticality: "critical", tags: ["dmz", "www", "portal"], owner: "Dział Promocji" },
  { ip: "10.0.1.7", hostnames: ["poczta.uczelnia.example", "mx.uczelnia.example"], os: "Linux 6.1 (Debian 12)", specs: [{ web: "roundcube", old: false }, { plain: "smtp" }, { plain: "submission" }, { plain: "imaps" }, { plain: "ssh" }], criticality: "critical", tags: ["dmz", "poczta"], owner: "Dział Informatyzacji" },
  { ip: "10.0.1.12", hostnames: ["usos.uczelnia.example"], os: "Linux 6.1 (Debian 12)", specs: [{ web: "usos", appVersion: "7.2.1" }, { plain: "ssh", old: false }], criticality: "critical", tags: ["dmz", "usos", "dane-osobowe"], owner: "Dział Nauczania" },
  { ip: "10.0.1.20", hostnames: ["moodle.uczelnia.example", "e-learning.uczelnia.example"], os: "Linux 6.1 (Debian 12)", specs: [{ web: "moodle", appVersion: "4.4.1", old: false }, { plain: "ssh", old: false }], criticality: "high", tags: ["dmz", "e-learning"], owner: "Centrum e-Learningu" },
  { ip: "10.0.1.33", hostnames: ["rekrutacja.uczelnia.example"], os: "Linux 6.1 (Debian 12)", specs: [{ web: "drupal", appVersion: "10.2.3", old: false }, { plain: "ssh", old: false }], criticality: "critical", tags: ["dmz", "rekrutacja", "dane-osobowe"], owner: "Dział Rekrutacji" },
  { ip: "10.0.2.33", hostnames: ["biblioteka.uczelnia.example"], os: "Linux 4.19 (Debian 10)", specs: [{ web: "drupal", appVersion: "7.98", old: true }, { plain: "ssh", appVersion: "7.4 (protocol 2.0)", old: true }], criticality: "high", tags: ["dmz", "www"], owner: "Biblioteka Główna" },
  { ip: "10.0.3.45", hostnames: ["konferencja.wydzial-fizyki.uczelnia.example"], os: "Linux 5.15 (Ubuntu 22.04)", specs: [{ web: "wordpress", port: 8443, tls: true, appVersion: "6.4.3", old: false, change: "new" }], criticality: "high", tags: ["dmz", "www"], owner: "Wydział Fizyki i Informatyki Stosowanej", change: "new" },
  { ip: "10.0.12.19", hostnames: ["rekrutacja-old.uczelnia.example"], os: "Linux 5.4 (Ubuntu 20.04)", specs: [{ web: "nginx_default", port: 443, tls: true, serverVersion: "1.24.0", old: false }], criticality: "medium", tags: ["serwerownia"], owner: "Dział Rekrutacji", change: "unstable", availability: "unstable" },
  { ip: "10.0.9.14", hostnames: ["db-admin.it.uczelnia.example"], os: "Linux 3.10 (CentOS 7)", specs: [{ web: "phpmyadmin", appVersion: "4.9.11", old: true }, { plain: "mysql", appVersion: "5.7.44", old: true }, { plain: "ssh", appVersion: "7.4 (protocol 2.0)", old: true }], criticality: "high", tags: ["serwerownia", "bazy-danych"], owner: "Dział Informatyzacji" },
  { ip: "10.0.10.4", hostnames: ["grafana.it.uczelnia.example"], specs: [{ web: "grafana", appVersion: "10.4.1", old: false }, { plain: "ssh", old: false }], criticality: "medium", tags: ["serwerownia", "monitoring-it"], owner: "Dział Informatyzacji" },
  { ip: "10.0.10.5", hostnames: ["kibana.it.uczelnia.example"], specs: [{ web: "kibana", appVersion: "7.10.2", old: true }, { plain: "ssh", old: false }], criticality: "medium", tags: ["serwerownia", "monitoring-it"], owner: "Dział Informatyzacji" },
  { ip: "10.0.10.6", hostnames: ["metryki.it.uczelnia.example"], specs: [{ plain: "ssh", old: false }, { web: "prometheus", change: "new" }], criticality: "medium", tags: ["serwerownia", "monitoring-it"], owner: "Dział Informatyzacji", change: "changed" },
  { ip: "10.0.10.7", hostnames: ["logi.wydzial-informatyki.uczelnia.example"], specs: [{ web: "elastic", appVersion: "7.17.18", old: false }, { plain: "ssh", old: false }], criticality: "high", tags: ["serwerownia"], owner: "Wydział Informatyki" },
  { ip: "10.0.20.8", hostnames: ["ci.wydzial-informatyki.uczelnia.example"], specs: [{ web: "jenkins", appVersion: "2.346.3", old: true }, { plain: "ssh", old: false }], criticality: "high", tags: ["serwerownia", "ci-cd"], owner: "Wydział Informatyki" },
  { ip: "10.0.236.8", hostnames: ["staging-api.wydzial-informatyki.uczelnia.example"], specs: [{ web: "tomcat", serverVersion: "9.0.85", old: false, change: "changed" }, { plain: "ssh", old: false }], criticality: "medium", tags: ["laboratorium", "staging"], owner: "Wydział Informatyki", change: "changed" },
  { ip: "10.0.236.20", hostnames: ["staging.uczelnia.example", "staging-rekrutacja.uczelnia.example"], specs: [{ web: "staging_portal" }, { plain: "ssh", old: false }], criticality: "medium", tags: ["laboratorium", "staging"], owner: "Dział Rekrutacji" },
  { ip: "10.0.236.21", hostnames: ["dev-ankiety.wydzial-informatyki.uczelnia.example"], specs: [{ web: "dev_app", change: "new" }], criticality: "low", tags: ["laboratorium"], owner: "Wydział Informatyki", change: "new" },
  { ip: "10.0.237.5", hostnames: ["jupyter.lab-ai.wydzial-informatyki.uczelnia.example"], specs: [{ web: "jupyter" }, { plain: "ssh", old: false }], criticality: "medium", tags: ["laboratorium", "ai"], owner: "Wydział Informatyki" },
  { ip: "10.0.224.10", hostnames: ["idrac-r740-01.mgmt.uczelnia.example"], device: "bmc", specs: [{ web: "idrac", appVersion: "iDRAC9 7.00.00.171", old: false }, { plain: "ipmi" }], criticality: "high", tags: ["zarządzanie"], owner: "Sekcja Sieci i Serwerowni" },
  { ip: "10.0.216.3", hostnames: ["ups-serwerownia-a.mgmt.uczelnia.example"], device: "iot", specs: [{ web: "apc_ups", old: true }, { plain: "snmp" }], criticality: "high", tags: ["zarządzanie"], owner: "Sekcja Sieci i Serwerowni" },
  { ip: "10.0.200.17", hostnames: ["kamera-brama-glowna.monitoring.uczelnia.example"], device: "camera", specs: [{ web: "camera_hik", appVersion: "DS-2CD2032-I", old: true, change: "new" }, { plain: "rtsp", change: "new" }, { plain: "hiksdk", change: "new" }], criticality: "medium", tags: ["monitoring"], owner: "Dział Ochrony Mienia", change: "new" },
  { ip: "10.0.33.40", hostnames: ["test-moodle.wydzial-informatyki.uczelnia.example"], specs: [{ web: "moodle", appVersion: "3.11.18", old: true }, { plain: "ssh", old: false }], criticality: "low", tags: ["laboratorium"], owner: "Wydział Informatyki" },
  { ip: "10.0.14.2", hostnames: ["gitlab.uczelnia.example"], specs: [{ web: "gitlab", appVersion: "17.2.0", old: false }, { plain: "ssh", old: false }], criticality: "high", tags: ["serwerownia", "ci-cd"], owner: "Dział Informatyzacji" },
  { ip: "10.0.14.3", hostnames: ["sso.uczelnia.example"], specs: [{ web: "keycloak", appVersion: "24.0.3" }], criticality: "critical", tags: ["serwerownia", "tożsamość"], owner: "Dział Informatyzacji" },
  { ip: "10.0.15.9", hostnames: ["nas-backup-01.it.uczelnia.example"], device: "storage", specs: [{ web: "synology", appVersion: "DSM 6.2.4", old: true }, { plain: "smb" }, { plain: "ssh", old: false }], criticality: "high", tags: ["backup"], owner: "Dział Informatyzacji" },
  { ip: "10.0.21.4", hostnames: ["redis-cache.it.uczelnia.example"], specs: [{ plain: "redis", appVersion: "6.0.16" }, { plain: "ssh", old: false }], criticality: "medium", tags: ["serwerownia"], owner: "Dział Informatyzacji" },
  { ip: "10.0.40.66", hostnames: ["ftp.wydzial-gornictwa.uczelnia.example"], specs: [{ plain: "ftp", appVersion: "2.3.4", old: true }, { plain: "ssh", old: false }], criticality: "medium", tags: ["serwerownia"], owner: "Wydział Górnictwa i Geoinżynierii" },
];

const ipToOff = (ip: string) => {
  const [, , c, d] = ip.split(".").map(Number);
  return c * 256 + d;
};

/* ------------------------------------------------------------------ */
/* Seed                                                                */
/* ------------------------------------------------------------------ */

function lastScanFinish(now: Date): Date {
  const z = zoned(now);
  const today = warsaw(z.y, z.mo, z.d, 5, 42);
  return today.getTime() <= now.getTime() ? today : warsaw(z.y, z.mo, z.d - 1, 5, 42);
}

export function createDB(): MockDB {
  const nowDate = new Date();
  const now = nowDate.getTime();
  const anchor = lastScanFinish(nowDate).getTime();
  const anchorIso = iso(anchor);
  const rng = mulberry32(20261121);

  /* ---------------- users & roles ---------------- */
  const roles: Role[] = BUILTIN_ROLES.map((r, idx) => ({
    id: `r-${idx + 1}`,
    key: r.key,
    name: r.name,
    description: r.description,
    builtin: true,
    permissions: [...r.permissions],
    users_count: 0,
  }));
  roles.push({
    id: "r-5",
    key: "custom-audit",
    name: "Audytor zewnętrzny",
    description: "Rola własna: wgląd w wyniki, zmiany i dziennik zdarzeń na czas audytu.",
    builtin: false,
    permissions: ["dashboard:read", "findings:read", "findings:export", "changes:read", "scans:read", "audit:read"],
    users_count: 0,
  });
  const mkUser = (
    id: string,
    login: string,
    name: string,
    roleId: string,
    active = true,
    lastLoginH: number | null = 3,
  ): User & { password: string } => ({
    id,
    login,
    name,
    email: `${login}@cbi.uczelnia.example`,
    role_id: roleId,
    role_name: roles.find((r) => r.id === roleId)!.name,
    active,
    last_login_at: lastLoginH === null ? null : iso(now - lastLoginH * HOUR),
    created_at: iso(now - 220 * DAY),
    password: "demo",
  });
  const users = [
    mkUser("u-1", "jan.kowalski", "Jan Kowalski", "r-1", true, 1),
    mkUser("u-2", "anna.nowak", "Anna Nowak", "r-2", true, 5),
    mkUser("u-3", "piotr.wisniewski", "Piotr Wiśniewski", "r-3", true, 20),
    mkUser("u-4", "maria.wojcik", "Maria Wójcik", "r-4", true, 46),
    mkUser("u-5", "katarzyna.zielinska", "Katarzyna Zielińska", "r-2", true, 70),
    mkUser("u-6", "tomasz.lewandowski", "Tomasz Lewandowski", "r-3", false, 900),
    mkUser("u-7", "audytor", "Audytor zewnętrzny", "r-5", true, null),
  ];
  for (const r of roles) r.users_count = users.filter((u) => u.role_id === r.id).length;

  /* ---------------- hosts ---------------- */
  const specialByOff = new Map(SPECIALS.map((s) => [ipToOff(s.ip), s]));
  const cands: { off: number; p: number }[] = [];
  for (let b = 0; b < 256; b++) {
    const d = BLOCK_DENSITY[blockType(b)];
    if (!d) continue;
    for (let i = 1; i < 255; i++) {
      const off = b * 256 + i;
      cands.push({ off, p: specialByOff.has(off) ? -1 : rng() / d });
    }
  }
  cands.sort((a, b) => a.p - b.p);
  const respondedOffs = cands.slice(0, RESPONDED).map((c) => c.off);
  const extraOffs = cands.slice(RESPONDED, RESPONDED + EXTRA).map((c) => c.off);

  const hosts: HostRec[] = [];
  const mkHost = (off: number, responded: boolean): HostRec => {
    const hr = rngFor("host", off);
    const b = off >> 8;
    const type = blockType(b);
    const special = specialByOff.get(off);
    const firstSeenMs = anchor - int(hr, 3, 520) * DAY - int(hr, 0, 20) * HOUR;
    const firstSeen = iso(firstSeenMs);
    const lastSeen = responded ? anchorIso : iso(anchor - int(hr, 1, 40) * DAY);
    const prof = special
      ? {
          device: special.device ?? ("server" as DeviceType),
          os: special.os ?? "Linux 6.1 (Debian 12)",
          specs: special.specs,
          hostnames: special.hostnames,
          criticality: special.criticality,
          tags: special.tags,
          owner: special.owner,
        }
      : randomProfile(type, off, hr);
    const services = makeServices(off, prof.specs, firstSeen, lastSeen, hr);
    return {
      id: `h-${off}`,
      ipInt: (10 << 24) + off,
      ip: offToIp(off),
      off,
      block: b,
      blockType: type,
      hostnames: prof.hostnames,
      device: prof.device,
      osGuess: prof.os,
      services,
      responded,
      availability: special?.availability ?? "active",
      change: special?.change ?? "unchanged",
      pattern: Array(8).fill(true),
      missCount: 0,
      firstSeen,
      lastSeen,
      owner: prof.owner,
      criticality: prof.criticality,
      tags: [...prof.tags],
      notes: null,
      overrides: {},
      recheckRequestedAt: null,
      lastRecheckAt: null,
      byHour: null,
    };
  };
  for (const off of respondedOffs) hosts.push(mkHost(off, true));
  for (const off of extraOffs) hosts.push(mkHost(off, false));
  hosts.sort((a, b) => a.off - b.off);
  const hostById = new Map(hosts.map((h) => [h.id, h]));
  const hostByOff = new Map(hosts.map((h) => [h.off, h]));

  /* availability: intermittent hosts (mostly workstations / Wi-Fi) */
  const respondedHosts = hosts.filter((h) => h.responded);
  const extraHosts = hosts.filter((h) => !h.responded);
  for (const h of respondedHosts) {
    const hr = rngFor("avail", h.off);
    const intermittent = ["dorm", "wifi", "office", "lab"].includes(h.blockType) ? 0.022 : 0.004;
    if (h.availability === "unstable" || chance(hr, intermittent)) {
      h.availability = "unstable";
      h.pattern = Array.from({ length: 8 }, (_, k) => (k === 7 ? true : chance(hr, 0.55)));
      if (h.pattern.every(Boolean)) h.pattern[3] = false;
    }
  }
  const goneHosts = sample(rngFor("gone"), extraHosts.filter((h) => !["empty"].includes(h.blockType)), 7);
  const goneSet = new Set(goneHosts.map((h) => h.id));
  for (const h of extraHosts) {
    const hr = rngFor("extra", h.off);
    if (goneSet.has(h.id)) {
      h.change = "gone";
      h.availability = "unstable";
      h.missCount = 1;
      h.pattern = [true, true, true, true, true, true, true, false];
      h.lastSeen = iso(anchor - DAY);
    } else if (chance(hr, 0.07)) {
      h.availability = "unstable";
      h.missCount = 1;
      h.pattern = Array.from({ length: 8 }, (_, k) => (k === 7 ? false : chance(hr, 0.5)));
      h.lastSeen = iso(anchor - 2 * DAY);
    } else {
      h.availability = "inactive";
      h.missCount = int(hr, 3, 24);
      const misses = Math.min(8, h.missCount);
      h.pattern = Array.from({ length: 8 }, (_, k) => k < 8 - misses);
    }
    for (const s of h.services) s.lastSeen = h.lastSeen;
  }

  /* hourly profile for unstable hosts (daytime re-checks) */
  for (const h of hosts) {
    if (h.availability !== "unstable") continue;
    const hr = rngFor("byhour", h.off);
    const office = ["office", "dorm", "wifi", "lab"].includes(h.blockType);
    h.byHour = Array.from({ length: 24 }, (_, hour) => {
      if (!office) return Math.round((0.45 + hr() * 0.4) * 100) / 100;
      const day = hour >= 8 && hour < 19;
      const evening = hour >= 19 && hour < 23;
      const base = day ? 0.86 : evening ? 0.55 : 0.12;
      return Math.round(Math.min(1, Math.max(0, base + (hr() - 0.5) * 0.18)) * 100) / 100;
    });
    h.lastRecheckAt = iso(now - int(hr, 2, 40) * HOUR);
  }

  /* ---------------- latest diff (#127 -> #128) ---------------- */
  const changes: Change[] = [];
  const dr = rngFor("diff-128");
  const changeId = (n: number) => `c-128-${n}`;
  const at = anchorIso;
  const hn = (h: HostRec) => h.hostnames[0] ?? null;
  const svcLabel = (s: ServiceRec) =>
    `${s.port}/${s.web ? (s.tls ? "https" : "http") : s.name}${s.product ? ` (${s.product}${s.version ? ` ${s.version}` : ""})` : ""}`;

  // New hosts
  const specialsNew = hosts.filter((h) => h.change === "new");
  const newPool = shuffle(
    dr,
    respondedHosts.filter((h) => h.change === "unchanged" && h.availability === "active" && ["cam", "lab", "office", "srv", "dorm", "print"].includes(h.blockType)),
  );
  const newHosts = [...specialsNew, ...newPool.slice(0, 30 - specialsNew.length)];
  for (const h of newHosts) {
    h.change = "new";
    h.firstSeen = at;
    for (const s of h.services) {
      s.change = "new";
      s.firstSeen = at;
    }
    h.pattern = [false, false, false, false, false, false, false, true];
  }
  // New services on existing hosts (prometheus special + 3 random)
  const svcNewHosts = [
    hostByOff.get(ipToOff("10.0.10.6"))!,
    ...shuffle(dr, respondedHosts.filter((h) => h.blockType === "srv" && h.change === "unchanged" && h.availability === "active")).slice(0, 3),
  ];
  for (const [k, h] of svcNewHosts.entries()) {
    if (k > 0) {
      const extra = makeServices(h.off, [{ plain: pick(dr, ["mysql", "redis", "postgres"]) }], at, at, dr).filter(
        (s) => !h.services.some((x) => x.port === s.port),
      );
      h.services.push(...extra);
      h.services.sort((a, b) => a.port - b.port);
    }
    h.change = "changed";
    for (const s of h.services) if (s.firstSeen === at || s.web === "prometheus") s.change = "new";
  }
  for (const [k, h] of newHosts.entries()) {
    changes.push({
      id: changeId(k),
      kind: "new",
      entity: "host",
      host_id: h.id,
      ip: h.ip,
      hostname: hn(h),
      port: null,
      summary: h.services.length
        ? `Nowy host z usługami: ${h.services.slice(0, 3).map(svcLabel).join(", ")}`
        : "Nowy host odpowiada na ping (brak otwartych portów)",
      fields: h.services.slice(0, 4).map((s) => ({ field: `service.${s.port}`, label: `Port ${s.port}/${s.protocol}`, before: null, after: svcLabel(s) })),
      confidence: Math.round((0.9 + dr() * 0.09) * 100) / 100,
      measurements: { responded: 3, total: 3 },
      detected_at: at,
    });
  }
  for (const h of svcNewHosts) {
    const s = h.services.find((x) => x.change === "new");
    if (!s) {
      h.change = "unchanged";
      continue;
    }
    changes.push({
      id: changeId(changes.length),
      kind: "new",
      entity: "service",
      host_id: h.id,
      ip: h.ip,
      hostname: hn(h),
      port: s.port,
      summary: `Nowa usługa: ${svcLabel(s)}`,
      fields: [{ field: `service.${s.port}`, label: `Port ${s.port}/${s.protocol}`, before: "zamknięty", after: svcLabel(s) }],
      confidence: 0.97,
      measurements: { responded: 3, total: 3 },
      detected_at: at,
    });
  }

  // Changed (tomcat special + 18 random)
  const tomcatHost = hostByOff.get(ipToOff("10.0.236.8"))!;
  const tomcatSvc = tomcatHost.services.find((s) => s.web === "tomcat")!;
  changes.push({
    id: changeId(changes.length),
    kind: "changed",
    entity: "service",
    host_id: tomcatHost.id,
    ip: tomcatHost.ip,
    hostname: hn(tomcatHost),
    port: 8080,
    summary: "Zmiana wersji Apache Tomcat: 9.0.65 → 9.0.85",
    fields: [
      { field: "service.8080.version", label: "Wersja (8080/http)", before: "9.0.65", after: "9.0.85" },
      { field: "http.8080.title", label: "Tytuł strony", before: "Apache Tomcat/9.0.65", after: "Apache Tomcat/9.0.85" },
    ],
    confidence: 0.92,
    measurements: { responded: 3, total: 3 },
    detected_at: at,
  });
  tomcatSvc.change = "changed";
  const changedPool = shuffle(
    dr,
    respondedHosts.filter((h) => h.change === "unchanged" && h.availability === "active" && h.services.some((s) => s.web || s.plain === "ssh")),
  ).slice(0, 18);
  for (const h of changedPool) {
    const web = h.services.find((s) => s.web && !s.redirectTo);
    const kind = web ? pick(dr, ["version", "title", "cert", "port"] as const) : "version";
    h.change = "changed";
    if (kind === "cert" && web?.tls) {
      web.change = "changed";
      web.certRenewedAt = anchor - HOUR;
      web.certDays = int(dr, 300, 397);
      changes.push({
        id: changeId(changes.length),
        kind: "changed",
        entity: "tls",
        host_id: h.id,
        ip: h.ip,
        hostname: hn(h),
        port: web.port,
        summary: "Odnowiony certyfikat TLS",
        fields: [
          { field: `tls.${web.port}.not_after`, label: "Ważny do", before: iso(anchor + int(dr, 2, 12) * DAY).slice(0, 10), after: iso(anchor + web.certDays * DAY).slice(0, 10) },
          { field: `tls.${web.port}.issuer`, label: "Wystawca", before: "GEANT TLS RSA 1", after: "HARICA GEANT TLS R1" },
        ],
        confidence: 0.99,
        measurements: { responded: 3, total: 3 },
        detected_at: at,
      });
    } else if (kind === "title" && web) {
      web.change = "changed";
      changes.push({
        id: changeId(changes.length),
        kind: "changed",
        entity: "http",
        host_id: h.id,
        ip: h.ip,
        hostname: hn(h),
        port: web.port,
        summary: "Zmiana tytułu strony",
        fields: [{ field: `http.${web.port}.title`, label: "Tytuł strony", before: "Strona w budowie", after: WEB_APPS[web.web!].title.replace(/\{.*?\}/g, "").trim() || "(pusty)" }],
        confidence: Math.round((0.8 + dr() * 0.15) * 100) / 100,
        measurements: { responded: 3, total: 3 },
        detected_at: at,
      });
    } else if (kind === "port") {
      const closed = pick(dr, [8081, 8888, 3000, 5432]);
      changes.push({
        id: changeId(changes.length),
        kind: "changed",
        entity: "service",
        host_id: h.id,
        ip: h.ip,
        hostname: hn(h),
        port: closed,
        summary: `Port ${closed}/tcp został zamknięty`,
        fields: [{ field: `service.${closed}`, label: `Port ${closed}/tcp`, before: "otwarty", after: "zamknięty" }],
        confidence: Math.round((0.75 + dr() * 0.2) * 100) / 100,
        measurements: { responded: 3, total: 3 },
        detected_at: at,
      });
    } else {
      const s = web ?? h.services.find((x) => x.plain === "ssh")!;
      const before = s.web ? s.serverVersion ?? "" : s.version ?? "";
      const after = s.web ? (s.serverVersion = bump(before)) : (s.version = bump(before));
      if (s.web && SERVER_PRODUCTS.has(s.product ?? "")) s.version = after;
      s.change = "changed";
      changes.push({
        id: changeId(changes.length),
        kind: "changed",
        entity: "service",
        host_id: h.id,
        ip: h.ip,
        hostname: hn(h),
        port: s.port,
        summary: `Zmiana wersji ${s.product ?? s.name}: ${before} → ${after}`,
        fields: [{ field: `service.${s.port}.version`, label: `Wersja (${s.port}/${s.name})`, before, after }],
        confidence: Math.round((0.85 + dr() * 0.14) * 100) / 100,
        measurements: { responded: 3, total: 3 },
        detected_at: at,
      });
    }
  }
  // Gone
  for (const h of goneHosts) {
    changes.push({
      id: changeId(changes.length),
      kind: "gone",
      entity: "host",
      host_id: h.id,
      ip: h.ip,
      hostname: hn(h),
      port: null,
      summary: `Host przestał odpowiadać (${h.services.length ? `ostatnio ${h.services.slice(0, 2).map(svcLabel).join(", ")}` : "brak usług"})`,
      fields: [{ field: "host.responded", label: "Odpowiada", before: "tak", after: "nie (1 skan bez odpowiedzi)" }],
      confidence: Math.round((0.6 + dr() * 0.25) * 100) / 100,
      measurements: { responded: 0, total: 3 },
      detected_at: at,
    });
  }
  // Unstable (special + 11)
  const unstablePool = [
    hostByOff.get(ipToOff("10.0.12.19"))!,
    ...shuffle(dr, respondedHosts.filter((h) => h.availability === "unstable" && h.change === "unchanged")).slice(0, 11),
  ];
  for (const h of unstablePool) {
    h.change = "unstable";
    if (h.ip === "10.0.12.19") {
      h.pattern = [true, true, false, true, true, false, true, true];
      h.byHour = Array.from({ length: 24 }, (_, hour) => (hour >= 7 && hour < 20 ? 0.92 : 0.35));
    }
    changes.push({
      id: changeId(changes.length),
      kind: "unstable",
      entity: "host",
      host_id: h.id,
      ip: h.ip,
      hostname: hn(h),
      port: h.services[0]?.port ?? null,
      summary: "Host odpowiada nieregularnie — 2 z 3 ostatnich pomiarów",
      fields: [{ field: "host.pattern", label: "Ostatnie pomiary", before: "3/3", after: "2/3" }],
      confidence: Math.round((0.55 + dr() * 0.3) * 100) / 100,
      measurements: { responded: 2, total: 3 },
      detected_at: at,
    });
  }

  /* ---------------- findings ---------------- */
  const findings: Finding[] = [];
  for (const h of hosts) findings.push(...findingsForHost(h, now, now));

  /* ---------------- targets ---------------- */
  const tDate = (d: number) => iso(now - d * DAY);
  const countIn = (first: number, size: number) =>
    respondedHosts.filter((h) => h.off >= first && h.off < first + size).length;
  const mkTarget = (
    id: string,
    value: string,
    type: Target["type"],
    address_count: number,
    name: string,
    owner: string,
    criticality: Criticality,
    tags: string[],
    extra: Partial<Target> = {},
  ): Target => ({
    id,
    value,
    type,
    address_count,
    name,
    owner,
    criticality,
    tags,
    notes: null,
    excluded: false,
    source: "manual",
    active_hosts: 0,
    last_scanned_at: anchorIso,
    created_at: tDate(210),
    updated_at: tDate(30),
    updated_by: "Anna Nowak",
    ...extra,
  });
  const targets: Target[] = [
    mkTarget("t-1", "10.0.0.0/18", "cidr", 16384, "Serwerownie i DMZ", "Dział Informatyzacji", "critical", ["serwerownia", "dmz"], { active_hosts: countIn(0, 16384) }),
    mkTarget("t-2", "10.0.64.0/18", "cidr", 16384, "Sieć wydziałowa", "Administracja centralna", "medium", ["wydziały"], { active_hosts: countIn(16384, 16384) }),
    mkTarget("t-3", "10.0.128.0/18", "cidr", 16384, "Akademiki i Wi-Fi", "Osiedle Studenckie", "low", ["akademiki", "wifi"], { active_hosts: countIn(32768, 16384), notes: "Adresy dynamiczne (DHCP) — wysoka zmienność hostów jest normalna." }),
    mkTarget("t-4", "10.0.192.0/19", "cidr", 8192, "Urządzenia i druk", "Dział Ochrony Mienia", "medium", ["iot", "druk", "monitoring"], { active_hosts: countIn(49152, 8192) }),
    mkTarget("t-5", "10.0.224.0/19", "cidr", 8192, "Zarządzanie i laboratoria", "Sekcja Sieci i Serwerowni", "high", ["zarządzanie", "laboratorium"], { active_hosts: countIn(57344, 8192) - 0 }),
    mkTarget("t-6", "10.0.250.0/24", "cidr", 256, "Systemy sterowania budynkami (BMS)", "Dział Techniczny", "critical", ["bms"], { excluded: true, active_hosts: 0, last_scanned_at: null, notes: "Wykluczone na prośbę Działu Technicznego — urządzenia wrażliwe na skanowanie." }),
    mkTarget("t-7", "uczelnia.example", "domain", 1, "Domena główna", "Dział Promocji", "critical", ["www"], { active_hosts: 1 }),
    mkTarget("t-8", "usos.uczelnia.example", "domain", 1, "USOSweb", "Dział Nauczania", "critical", ["usos"], { active_hosts: 1 }),
    mkTarget("t-9", "moodle.uczelnia.example", "domain", 1, "Platforma e-learningowa", "Centrum e-Learningu", "high", ["e-learning"], { active_hosts: 1 }),
    mkTarget("t-10", "poczta.uczelnia.example", "domain", 1, "Poczta uczelniana", "Dział Informatyzacji", "critical", ["poczta"], { active_hosts: 1 }),
    mkTarget("t-11", "rekrutacja.uczelnia.example", "domain", 1, "System rekrutacji", "Dział Rekrutacji", "critical", ["rekrutacja"], { active_hosts: 1 }),
    mkTarget("t-12", "biblioteka.uczelnia.example", "domain", 1, "Biblioteka Główna", "Biblioteka Główna", "medium", ["www"], { active_hosts: 1, source: "import" }),
    mkTarget("t-13", "staging.uczelnia.example", "domain", 1, "Staging rekrutacji", "Dział Rekrutacji", "medium", ["staging"], { active_hosts: 1, source: "import" }),
    mkTarget("t-14", "10.0.1.12", "ip", 1, "Serwer USOS (produkcja)", "Dział Nauczania", "critical", ["usos"], { active_hosts: 1 }),
  ];

  /* ---------------- profiles & schedules ---------------- */
  const profiles: ScanProfile[] = [
    { id: "p-1", name: "Standardowy", description: "1000 najpopularniejszych portów, odcisk HTTP/HTTPS i wszystkie sygnatury.", builtin: true, ports: { preset: "top1000", custom: "" }, rate_limit_rps: 500, max_concurrency: 64, nmap_timing: "T3", host_timeout_s: 120, http_probe: true, tls_probe: true, follow_redirects: true, max_redirects: 3, signatures: "all", signature_ids: [], unstable_retries: 3, batch_strategy: "auto", batch_prefix: 22 },
    { id: "p-2", name: "Szybki przegląd", description: "100 portów, bez sygnatur — do weryfikacji dostępności.", builtin: true, ports: { preset: "top100", custom: "" }, rate_limit_rps: 800, max_concurrency: 96, nmap_timing: "T4", host_timeout_s: 60, http_probe: true, tls_probe: false, follow_redirects: false, max_redirects: 0, signatures: "none", signature_ids: [], unstable_retries: 1, batch_strategy: "auto", batch_prefix: 21 },
    { id: "p-3", name: "Porty dozwolone (laboratorium AGH)", description: "Wyłącznie porty z listy dopuszczonej do testów.", builtin: false, ports: { preset: "allowed", custom: "" }, rate_limit_rps: 300, max_concurrency: 32, nmap_timing: "T3", host_timeout_s: 120, http_probe: true, tls_probe: true, follow_redirects: true, max_redirects: 3, signatures: "all", signature_ids: [], unstable_retries: 3, batch_strategy: "auto", batch_prefix: 23 },
    { id: "p-4", name: "Ostrożny — urządzenia IoT", description: "Niskie tempo i timing T2 dla drukarek, kamer i BMC.", builtin: false, ports: { preset: "custom", custom: "21-23,80,443,554,623,631,8000,8080,8443,9100" }, rate_limit_rps: 50, max_concurrency: 8, nmap_timing: "T2", host_timeout_s: 300, http_probe: true, tls_probe: true, follow_redirects: true, max_redirects: 2, signatures: "selected", signature_ids: ["sig-b12", "sig-b13", "sig-b14", "sig-c5"], unstable_retries: 2, batch_strategy: "fixed", batch_prefix: 24 },
  ];
  const win = { start: "22:00", end: "06:00", timezone: "Europe/Warsaw" };
  const nz = zoned(nowDate);
  const tonight = warsaw(nz.y, nz.mo, nz.d + (nz.h >= 22 ? 1 : 0), 22, 0);
  const schedules: Schedule[] = [
    { id: "sch-1", name: "Nocny pełny przegląd", enabled: true, target_ids: ["t-1", "t-2", "t-3", "t-4", "t-5", "t-7", "t-8", "t-9", "t-10", "t-11", "t-12", "t-13"], profile_id: "p-1", window: win, days: [1, 2, 3, 4, 5, 6, 7], frequency: "daily", cron: null, on_window_exceeded: "pause_resume", next_run_at: iso(tonight), last_run_id: "scan-128", created_at: tDate(200) },
    { id: "sch-2", name: "Urządzenia IoT — tygodniowo", enabled: true, target_ids: ["t-4"], profile_id: "p-4", window: { start: "01:00", end: "05:00", timezone: "Europe/Warsaw" }, days: [6], frequency: "weekly", cron: null, on_window_exceeded: "pause_resume", next_run_at: iso(warsaw(nz.y, nz.mo, nz.d + ((6 - nz.dow + 7) % 7 || 7), 1, 0)), last_run_id: null, created_at: tDate(120) },
    { id: "sch-3", name: "Pomiary kontrolne w dzień (hosty niestabilne)", enabled: true, target_ids: ["t-2", "t-3"], profile_id: "p-2", window: { start: "10:00", end: "16:00", timezone: "Europe/Warsaw" }, days: [1, 2, 3, 4, 5], frequency: "cron", cron: "0 10,13,15 * * 1-5", on_window_exceeded: "stop", next_run_at: iso(warsaw(nz.y, nz.mo, nz.d + 1, 10, 0)), last_run_id: null, created_at: tDate(45) },
  ];

  /* ---------------- scans history, timeline, trend ---------------- */
  const scans: ScanRun[] = [];
  const timeline: ChangesTimelinePoint[] = [];
  const trend: { scan_number: number; at: string; value: number }[] = [];
  const hr = rngFor("history");
  // 31 nights back; one 2-window run (#121) skips a night, #125 is an import.
  let number = 128;
  let night = 0;
  const runs: ScanRun[] = [];
  let value = RESPONDED;
  while (number >= 99) {
    const finish = anchor - night * DAY;
    const isImport = number === 125;
    const twoWindows = number === 121;
    const cancelled = number === 117;
    const durationS = isImport ? 4 : twoWindows ? 9 * 3600 + 50 * 60 : cancelled ? 2 * 3600 + 14 * 60 : 7 * 3600 + int(hr, -25, 20) * 60;
    const finishedAt = isImport
      ? warsaw(zoned(new Date(finish)).y, zoned(new Date(finish)).mo, zoned(new Date(finish)).d, 14, 10).getTime()
      : twoWindows
        ? finish - 4 * HOUR
        : cancelled
          ? finish - 5 * HOUR
          : finish + int(hr, -12, 10) * MIN;
    const startedAt = twoWindows ? finishedAt - DAY - 3 * HOUR - 50 * MIN : finishedAt - durationS * 1000;
    const nNew = number === 128 ? 34 : number === 110 ? 61 : int(hr, 8, 40);
    const nChanged = number === 128 ? 19 : int(hr, 6, 28);
    const nGone = number === 128 ? 7 : int(hr, 2, 14);
    const nUnstable = number === 128 ? 12 : int(hr, 5, 16);
    const run: ScanRun = {
      id: `scan-${number}`,
      number,
      name: isImport ? "Import: wyniki nmap z laboratorium" : twoWindows ? "Nocny pełny przegląd (2 okna)" : "Nocny pełny przegląd",
      status: cancelled ? "cancelled" : "completed",
      phase: null,
      source: isImport ? "import" : "scanner",
      profile_id: isImport ? null : "p-1",
      profile_name: isImport ? null : "Standardowy",
      schedule_id: isImport ? null : "sch-1",
      target_ids: isImport ? ["t-5"] : schedules[0].target_ids,
      targets_label: isImport ? "10.0.224.0/19" : "5 zakresów, 6 domen (65 536 adresów)",
      address_count: isImport ? 8192 : 65536,
      progress: cancelled ? 0.31 : 1,
      batches_total: isImport ? 1 : 64,
      batches_done: cancelled ? 20 : isImport ? 1 : 64,
      rate_rps: isImport ? 0 : int(hr, 440, 498),
      rate_limit_rps: 500,
      window: isImport ? null : win,
      window_ends_at: null,
      resume_at: null,
      windows_used: twoWindows ? 2 : isImport ? 0 : 1,
      started_at: iso(startedAt),
      finished_at: iso(finishedAt),
      duration_s: durationS,
      eta_s: null,
      stats: {
        hosts_alive: isImport ? 212 : value,
        services: isImport ? 640 : Math.round(value * 2.46),
        http_services: isImport ? 118 : Math.round(value * 0.41),
        findings: isImport ? 9 : findings.length - int(hr, 0, 40),
        new: cancelled || isImport ? 0 : nNew,
        changed: cancelled || isImport ? 0 : nChanged,
        gone: cancelled || isImport ? 0 : nGone,
        unstable: cancelled || isImport ? 0 : nUnstable,
      },
      error: cancelled ? null : null,
      tags: twoWindows ? ["przekroczone-okno"] : [],
      notes: cancelled
        ? "Przerwano ręcznie — prace serwisowe w serwerowni A."
        : twoWindows
          ? "Skan nie zmieścił się w oknie 22:00–06:00: wstrzymany o 06:00 i dokończony w kolejnym oknie."
          : isImport
            ? "Wyniki zaimportowane z pliku CSV (nmap -oX przekonwertowany)."
            : null,
      created_by: isImport ? "Katarzyna Zielińska" : "Harmonogram",
    };
    runs.push(run);
    if (!isImport && !cancelled) {
      timeline.push({ scan_id: run.id, scan_number: number, at: run.finished_at!, new: nNew, changed: nChanged, gone: nGone, unstable: nUnstable });
      trend.push({ scan_number: number, at: run.finished_at!, value });
      value -= nNew - nGone + int(hr, -6, 6);
      if (number === 128) value = 12_368;
    }
    number -= 1;
    if (!isImport) night += twoWindows ? 2 : 1;
  }
  runs.sort((a, b) => a.number - b.number);
  scans.push(...runs);
  timeline.sort((a, b) => a.scan_number - b.scan_number);
  trend.sort((a, b) => a.scan_number - b.scan_number);

  /* ---------------- signatures ---------------- */
  const countWeb = (key: string, pred: (s: ServiceRec) => boolean = () => true) =>
    respondedHosts.reduce((n, h) => n + h.services.filter((s) => s.web === key && !s.redirectTo && pred(s)).length, 0);
  const sig = (
    id: string,
    name: string,
    description: string,
    category: Signature["category"],
    technology: string | null,
    conditions: Signature["match"]["conditions"],
    matches: number,
    extra: Partial<Signature> = {},
  ): Signature => ({
    id,
    name,
    description,
    category,
    technology,
    severity: "info",
    score_weight: category === "technology" ? 0 : 15,
    enabled: true,
    source: "builtin",
    match: { operator: "and", conditions },
    tags: [],
    author: "CBI AGH (wbudowane)",
    created_at: tDate(300),
    updated_at: tDate(90),
    matches_last_scan: matches,
    version: 1,
    ...extra,
  });
  const signatures: Signature[] = [
    sig("sig-b1", "WordPress — znacznik generatora", "Rozpoznaje WordPressa po meta generator i ścieżce logowania.", "technology", "WordPress", [{ type: "html", op: "regex", value: 'content="WordPress ([\\d.]+)"' }, { type: "path", path: "/wp-login.php", op: "exists", expect_status: 200 }], countWeb("wordpress")),
    sig("sig-b2", "Joomla! — panel /administrator", "Strona logowania panelu Joomla!.", "admin_panel", "Joomla!", [{ type: "path", path: "/administrator/", op: "contains", value: "Joomla", expect_status: 200 }], countWeb("joomla")),
    sig("sig-b3", "Drupal — nagłówek X-Generator", "Nagłówek X-Generator ujawnia Drupala i wersję główną.", "technology", "Drupal", [{ type: "header", name: "X-Generator", op: "contains", value: "Drupal" }], countWeb("drupal")),
    sig("sig-b4", "Moodle — ciasteczko MoodleSession", "Ciasteczko sesji Moodle.", "technology", "Moodle", [{ type: "cookie", name: "MoodleSession", op: "exists" }], countWeb("moodle")),
    sig("sig-b5", "USOSweb — tytuł strony", "Tytuł strony zawiera „USOSweb”.", "technology", "USOSweb", [{ type: "title", op: "contains", value: "USOSweb" }], countWeb("usos")),
    sig("sig-b6", "Apache Tomcat — Manager App", "Panel /manager/html odpowiada 401 z realm Tomcat Manager.", "admin_panel", "Apache Tomcat", [{ type: "path", path: "/manager/html", op: "exists", expect_status: 401 }], countWeb("tomcat")),
    sig("sig-b7", "Jenkins — nagłówek X-Jenkins", "Wersja Jenkinsa z nagłówka X-Jenkins.", "technology", "Jenkins", [{ type: "header", name: "X-Jenkins", op: "exists" }, { type: "version", op: "regex", extract: "X-Jenkins: ([\\d.]+)" }], countWeb("jenkins")),
    sig("sig-b8", "phpMyAdmin — strona logowania", "Panel phpMyAdmin dostępny bez VPN.", "admin_panel", "phpMyAdmin", [{ type: "path", path: "/phpmyadmin/", op: "contains", value: "phpMyAdmin", expect_status: 200 }], countWeb("phpmyadmin")),
    sig("sig-b9", "Grafana — strona logowania", "Tytuł „Grafana” i ciasteczko grafana_session.", "admin_panel", "Grafana", [{ type: "title", op: "equals", value: "Grafana" }], countWeb("grafana")),
    sig("sig-b10", "Kibana — nagłówek kbn-name", "Nagłówek kbn-name identyfikuje Kibanę.", "technology", "Kibana", [{ type: "header", name: "kbn-name", op: "exists" }], countWeb("kibana")),
    sig("sig-b11", "GitLab — hash favicony", "Favicona GitLaba (mmh3).", "technology", "GitLab", [{ type: "favicon_hash", op: "equals", value: "1278323681" }], countWeb("gitlab")),
    sig("sig-b12", "Dell iDRAC — strona logowania", "Kontroler BMC serwera Dell.", "admin_panel", "Dell iDRAC", [{ type: "title", op: "contains", value: "iDRAC" }], countWeb("idrac")),
    sig("sig-b13", "Hikvision — hash favicony", "Kamery Hikvision rozpoznawane po faviconie.", "iot", "Hikvision", [{ type: "favicon_hash", op: "equals", value: "999357577" }], countWeb("camera_hik")),
    sig("sig-b14", "HP LaserJet — serwer EWS", "Wbudowany serwer WWW drukarek HP.", "iot", "HP Embedded Web Server", [{ type: "header", name: "Server", op: "contains", value: "HP HTTP Server" }], countWeb("printer_hp")),
    sig("sig-b15", "Ujawniona wersja PHP", "X-Powered-By zawiera numer wersji PHP.", "header", "PHP", [{ type: "header", name: "X-Powered-By", op: "regex", value: "PHP/[\\d.]+" }], respondedHosts.reduce((n, h) => n + h.services.filter((s) => s.web && WEB_APPS[s.web].poweredBy?.startsWith("PHP") && !s.redirectTo).length, 0)),
    sig("sig-b16", "Token profilera (X-Debug-Token)", "Typowy dla trybu debugowania Symfony/Laravel.", "staging", null, [{ type: "header", name: "X-Debug-Token", op: "exists" }], countWeb("staging_portal")),
    sig("sig-b17", "Django — DEBUG = True", "Strona błędu Django w trybie debugowania.", "staging", "Django", [{ type: "html", op: "contains", value: "DEBUG = True" }], countWeb("dev_app")),
    sig("sig-b18", "Prometheus bez uwierzytelnienia", "Interfejs /graph dostępny bez logowania.", "exposure", "Prometheus", [{ type: "path", path: "/graph", op: "exists", expect_status: 200 }, { type: "title", op: "contains", value: "Prometheus" }], countWeb("prometheus")),
    sig("sig-c1", "Nagłówek X-Environment: staging", "Wewnętrzna konwencja: aplikacje testowe ustawiają X-Environment.", "staging", null, [{ type: "header", name: "X-Environment", op: "equals", value: "staging" }], countWeb("staging_portal"), { source: "custom", author: "Anna Nowak", created_at: tDate(60), updated_at: tDate(12), version: 3, score_weight: 20, tags: ["konwencja-cbi"] }),
    sig("sig-c2", "Stary Apache 2.2", "Serwer Apache 2.2 nie jest wspierany od 2018 r.", "outdated", "Apache HTTP Server", [{ type: "header", name: "Server", op: "regex", value: "Apache/2\\.2\\." }], countWeb("apache_default", (s) => s.serverVersion?.startsWith("2.2") ?? false), { source: "custom", author: "Piotr Wiśniewski", created_at: tDate(40), updated_at: tDate(40), score_weight: 25 }),
    sig("sig-c3", "Stopka „Powered by Joomla! 3”", "Joomla! 3 osiągnęła koniec wsparcia w 2023 r.", "outdated", "Joomla!", [{ type: "html", op: "regex", value: "Joomla! 3\\.[\\d.]+" }], countWeb("joomla", (s) => s.old), { source: "custom", author: "Piotr Wiśniewski", created_at: tDate(38), updated_at: tDate(20), version: 2, score_weight: 25 }),
    sig("sig-c4", "USOS — strona logowania CAS", "Centralny System Uwierzytelniania wystawiony poza domeną główną.", "admin_panel", "USOS CAS", [{ type: "path", path: "/cas/login", op: "contains", value: "Centralny System Uwierzytelniania", expect_status: 200 }], 0, { source: "custom", author: "Anna Nowak", created_at: tDate(9), updated_at: tDate(9), score_weight: 15 }),
    sig("sig-c5", "APC RomPager 4.01", "Stara wersja serwera RomPager w kartach zarządzających UPS.", "outdated", "Allegro RomPager", [{ type: "header", name: "Server", op: "contains", value: "RomPager/4.01" }], countWeb("apc_ups"), { source: "custom", author: "Katarzyna Zielińska", created_at: tDate(25), updated_at: tDate(25), score_weight: 20 }),
    sig("sig-c6", "Jupyter bez tokenu (szkic)", "Strona główna Jupytera dostępna bez tokenu.", "exposure", "Jupyter", [{ type: "title", op: "contains", value: "Select or create a notebook" }], countWeb("jupyter"), { source: "custom", author: "Jan Kowalski", enabled: false, created_at: tDate(2), updated_at: tDate(2), score_weight: 30 }),
  ];

  /* ---------------- audit ---------------- */
  const actor = (u: User) => ({ id: u.id, name: u.name, role: u.role_name });
  const system = { id: "system", name: "Harmonogram", role: "System" };
  const audit: AuditEvent[] = [];
  let aid = 0;
  const ev = (minutesAgo: number, a: AuditEvent["actor"], action: AuditEvent["action"], resource: string, label: string | null, summary: string, changesList: AuditEvent["changes"] = [], resourceId: string | null = null) =>
    audit.push({ id: `a-${++aid}`, at: iso(now - minutesAgo * MIN), actor: a, action, resource, resource_id: resourceId, resource_label: label, summary, changes: changesList });
  ev(35, actor(users[0]), "login", "session", null, "Zalogowano do systemu");
  ev(52, actor(users[2]), "update", "finding", "Panel administracyjny: phpMyAdmin (10.0.9.14)", "Zmieniono status znaleziska", [{ field: "status", label: "Status", before: "Do analizy", after: "W analizie" }], "f-2318-80-admin_panel");
  ev(80, actor(users[1]), "update", "host", "10.0.236.8", "Uzupełniono właściciela hosta", [{ field: "owner", label: "Właściciel", before: "Wydział Informatyki", after: "Zespół Projektów Studenckich WI" }], "h-60424");
  ev(140, actor(users[1]), "defectdojo_export", "finding", "4 znaleziska", "Wysłano 4 znaleziska do DefectDojo (finding informacyjny)");
  ev(190, actor(users[3]), "export", "finding", "znaleziska.csv", "Pobrano raport znalezisk (CSV, 212 wierszy)");
  ev(240, actor(users[2]), "update", "signature", "Stopka „Powered by Joomla! 3”", "Zmieniono wyrażenie regularne sygnatury", [{ field: "match", label: "Warunek", before: "Joomla! 3", after: "Joomla! 3\\.[\\d.]+" }], "sig-c3");
  ev(Math.round((now - anchor) / MIN) + 1, system, "scan_start", "scan", "#128", "Zakończono skan #128: 34 nowe, 19 zmienionych, 7 zniknęło, 12 niestabilnych", [], "scan-128");
  ev(Math.round((now - anchor) / MIN) + 7 * 60 + 10, system, "scan_start", "scan", "#128", "Uruchomiono skan #128 z harmonogramu „Nocny pełny przegląd”", [], "scan-128");
  ev(26 * 60, actor(users[0]), "update", "role", "Audytor zewnętrzny", "Dodano uprawnienie do dziennika zdarzeń", [{ field: "permissions", label: "Uprawnienia", before: "5", after: "6" }], "r-5");
  ev(27 * 60, actor(users[0]), "create", "user", "Audytor zewnętrzny", "Utworzono konto z rolą Audytor zewnętrzny", [], "u-7");
  ev(30 * 60, actor(users[1]), "create", "target", "staging.uczelnia.example", "Zaimportowano 2 cele z pliku cele-rekrutacja.csv", [], "t-13");
  ev(31 * 60, actor(users[1]), "update", "target", "10.0.250.0/24", "Wykluczono zakres ze skanowania", [{ field: "excluded", label: "Wykluczony", before: "nie", after: "tak" }], "t-6");
  ev(50 * 60, actor(users[4]), "import", "scan", "#125", "Zaimportowano wyniki skanu z pliku nmap-lab.csv (212 hostów)", [], "scan-125");
  ev(54 * 60, actor(users[0]), "reveal", "service", "10.0.236.20:443 laravel_session", "Odsłonięto wartość ciasteczka (dane wrażliwe)");
  ev(3 * 24 * 60, actor(users[0]), "update", "settings", "Bezpieczeństwo skanowania", "Zmieniono limit zapytań", [{ field: "max_rate_rps", label: "Limit zapytań/s", before: "800", after: "500" }]);
  ev(4 * 24 * 60, actor(users[2]), "update", "finding", "Środowisko testowe: staging.uczelnia.example", "Oznaczono jako potwierdzone", [{ field: "status", label: "Status", before: "W analizie", after: "Potwierdzone" }]);
  ev(5 * 24 * 60, actor(users[1]), "create", "signature", "Nagłówek X-Environment: staging", "Utworzono sygnaturę własną", [], "sig-c1");
  ev(7 * 24 * 60, actor(users[0]), "rotate_key", "encryption", "kms-key-2026-11", "Wykonano rotację klucza szyfrowania danych");
  for (let k = 0; k < 40; k++) {
    const u = pick(hr, users.slice(0, 5));
    const kind = pick(hr, ["login", "update", "export"] as const);
    ev(8 * 24 * 60 + k * 170 + int(hr, 0, 60), actor(u), kind, kind === "login" ? "session" : kind === "export" ? "host" : "finding", kind === "login" ? null : kind === "export" ? "hosty.json" : `Znalezisko ${int(hr, 100, 900)}`, kind === "login" ? "Zalogowano do systemu" : kind === "export" ? "Pobrano eksport hostów (JSON)" : "Dodano notatkę do znaleziska");
  }
  audit.sort((a, b) => b.at.localeCompare(a.at));

  /* ---------------- integrations, settings ---------------- */
  const engines: Engine[] = [
    { name: "nmap", version: "7.97", status: "ok", path: "/usr/bin/nmap", purpose: "Wykrywanie hostów i identyfikacja usług (-sn, -sV)", last_used_at: anchorIso },
    { name: "naabu", version: "2.3.5", status: "ok", path: "/usr/local/bin/naabu", purpose: "Szybkie skanowanie portów (SYN)", last_used_at: anchorIso },
    { name: "httpx", version: "1.7.1", status: "ok", path: "/usr/local/bin/httpx", purpose: "Odcisk HTTP/HTTPS: tytuł, nagłówki, technologie", last_used_at: anchorIso },
    { name: "tlsx", version: "1.2.0", status: "ok", path: "/usr/local/bin/tlsx", purpose: "Certyfikaty i parametry TLS", last_used_at: anchorIso },
    { name: "nuclei", version: "3.4.10", status: "ok", path: "/usr/local/bin/nuclei", purpose: "Sygnatury (wyłącznie szablony informacyjne)", last_used_at: anchorIso },
  ];

  return {
    seededAt: now,
    users,
    roles,
    targets,
    profiles,
    schedules,
    scans,
    batches: new Map(),
    sims: new Map(),
    hosts,
    hostById,
    hostByOff,
    findings,
    latestDiff: { baseId: "scan-127", headId: "scan-128", changes },
    timeline,
    trend,
    signatures,
    audit,
    settings: {
      scan_safety: {
        max_rate_rps: 500,
        max_concurrency: 64,
        allowed_ports:
          "21-23,25,53,80,110,123,135,139,143,161,389,443,445,465,554,587,623,631,636,993,995,1433,3000,3306,3389,5000-5001,5432,5601,5900,5985,6379,8000-8099,8291,8443,8888,9000-9100,9200,27017",
        excluded_cidrs: ["10.0.250.0/24"],
        user_agent: "CBI-AGH-ASI/0.1 (+https://cbi.uczelnia.example/skanowanie)",
        max_http_requests_per_host: 12,
      },
      change_detection: {
        inactive_after_misses: 3,
        unstable_retries: 3,
        change_confidence_threshold: 0.7,
        recheck_interval_minutes: 120,
      },
      retention: { scans_days: 180, audit_days: 365 },
      default_window: win,
    },
    encryption: {
      enabled: true,
      algorithm: "AES-256-GCM",
      provider: "PostgreSQL pgcrypto + klucz z menedżera sekretów",
      key_id: "kms-key-2026-11",
      key_created_at: iso(now - 7 * DAY),
      rotated_at: iso(now - 7 * DAY),
      encrypted_fields: [
        { table: "http_findings", column: "headers", description: "Nagłówki odpowiedzi HTTP" },
        { table: "http_findings", column: "cookies", description: "Nazwy i wartości ciasteczek" },
        { table: "http_findings", column: "tls_certificate", description: "Certyfikaty TLS (PEM)" },
        { table: "http_findings", column: "body_excerpt", description: "Fragmenty treści stron" },
        { table: "services", column: "banner", description: "Banery usług" },
        { table: "findings", column: "evidence", description: "Dowody znalezisk" },
        { table: "findings", column: "notes", description: "Notatki analityków" },
        { table: "hosts", column: "notes", description: "Notatki o hostach" },
        { table: "integrations", column: "defectdojo_token", description: "Token API DefectDojo" },
        { table: "users", column: "email", description: "Adresy e-mail użytkowników" },
      ],
      last_check_at: iso(now - 10 * MIN),
    },
    defectdojo: {
      enabled: true,
      url: "https://defectdojo.cbi.uczelnia.example",
      api_token_set: true,
      api_token_masked: "••••••••••••3f9a",
      token: "dd-demo-token-3f9a",
      product_id: 7,
      product_name: "Infrastruktura kampusowa",
      engagement_id: 42,
      engagement_name: "ASI — monitoring ciągły 2026",
      auto_export: false,
      min_score: 70,
      export_as: "finding",
      verify_tls: true,
      last_test: { ok: true, at: iso(now - 26 * HOUR), version: "2.39.1", latency_ms: 84, message: "Połączono, token ważny" },
    },
    ddExports: [
      { id: "dd-6", at: iso(now - 140 * MIN), by: "Anna Nowak", count: 4, as: "finding", status: "success", message: "Utworzono 4 findingi w „ASI — monitoring ciągły 2026”" },
      { id: "dd-5", at: iso(now - 3 * DAY), by: "Piotr Wiśniewski", count: 11, as: "finding", status: "success", message: "Utworzono 11 findingów" },
      { id: "dd-4", at: iso(now - 4 * DAY), by: "Anna Nowak", count: 2, as: "evidence", status: "success", message: "Dodano 2 załączniki do istniejących findingów" },
      { id: "dd-3", at: iso(now - 6 * DAY), by: "Anna Nowak", count: 7, as: "finding", status: "partial", message: "Utworzono 6 z 7 — jeden endpoint odrzucony (duplikat)" },
      { id: "dd-2", at: iso(now - 9 * DAY), by: "Jan Kowalski", count: 1, as: "finding", status: "failed", message: "Błąd 401: token wygasł (odnowiono tego samego dnia)" },
      { id: "dd-1", at: iso(now - 9 * DAY), by: "Jan Kowalski", count: 19, as: "finding", status: "success", message: "Utworzono 19 findingów" },
    ],
    engines,
    seq: 1000,
  };
}

/** Build a brand-new host at `off` (used when a simulated scan discovers it). */
export function spawnHost(off: number, at: string, rng: Rng): HostRec {
  const type = blockType(off >> 8);
  const prof = randomProfile(type, off, rng);
  const services = makeServices(off, prof.specs, at, at, rng).map((s) => ({ ...s, change: "new" as const }));
  return {
    id: `h-${off}`,
    ipInt: (10 << 24) + off,
    ip: offToIp(off),
    off,
    block: off >> 8,
    blockType: type,
    hostnames: prof.hostnames,
    device: prof.device,
    osGuess: prof.os,
    services,
    responded: true,
    availability: "active",
    change: "new",
    pattern: [false, false, false, false, false, false, false, true],
    missCount: 0,
    firstSeen: at,
    lastSeen: at,
    owner: prof.owner,
    criticality: prof.criticality,
    tags: [...prof.tags],
    notes: null,
    overrides: {},
    recheckRequestedAt: null,
    lastRecheckAt: null,
    byHour: null,
  };
}

export function bumpVersion(v: string): string {
  return bump(v);
}

function bump(v: string): string {
  const m = /^(\d+)\.(\d+)(?:\.(\d+))?(.*)$/.exec(v);
  if (!m) return v ? `${v}-1` : "1.0";
  const patch = m[3] !== undefined ? `.${Number(m[3]) + 1 + (Number(m[3]) % 3)}` : `.${Number(m[2]) + 1}`;
  return m[3] !== undefined ? `${m[1]}.${m[2]}${patch}${m[4]}` : `${m[1]}${patch}${m[4]}`;
}
