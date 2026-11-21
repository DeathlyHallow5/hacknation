import type {
  AuditAction,
  Availability,
  ChangeState,
  Criticality,
  DeviceType,
  FindingCategory,
  FindingStatus,
  ScanPhase,
  ScanStatus,
  SignatureConditionType,
  TargetType,
  TechCategory,
} from "@/lib/api/types";

export const CHANGE_LABEL: Record<ChangeState, string> = {
  new: "Nowy",
  changed: "Zmieniony",
  gone: "Zniknął",
  unstable: "Niestabilny",
  unchanged: "Bez zmian",
};

/** Plural/summary form used in counters ("Nowe 34"). */
export const CHANGE_LABEL_PLURAL: Record<Exclude<ChangeState, "unchanged">, string> = {
  new: "Nowe",
  changed: "Zmienione",
  gone: "Zniknęły",
  unstable: "Niestabilne",
};

/** Forms for "number + adjective" via countLabel: 1 nowy, 34 nowe, 19 zmienionych, 7 zniknęło. */
export const CHANGE_COUNT_FORMS: Record<Exclude<ChangeState, "unchanged">, [string, string, string]> = {
  new: ["nowy", "nowe", "nowych"],
  changed: ["zmieniony", "zmienione", "zmienionych"],
  gone: ["zniknął", "zniknęły", "zniknęło"],
  unstable: ["niestabilny", "niestabilne", "niestabilnych"],
};

export const AVAILABILITY_LABEL: Record<Availability, string> = {
  active: "Aktywny",
  unstable: "Niestabilny",
  inactive: "Nieaktywny",
};

export const CRITICALITY_LABEL: Record<Criticality, string> = {
  low: "Niska",
  medium: "Średnia",
  high: "Wysoka",
  critical: "Krytyczna",
};

export const TARGET_TYPE_LABEL: Record<TargetType, string> = {
  ip: "Adres IP",
  cidr: "Zakres CIDR",
  domain: "Domena",
};

export const FINDING_CATEGORY_LABEL: Record<FindingCategory, string> = {
  admin_panel: "Panel administracyjny",
  staging: "Środowisko testowe",
  outdated: "Przestarzały komponent",
  header: "Interesujący nagłówek",
  cookie: "Ciasteczko",
  tls: "Certyfikat TLS",
  exposure: "Usługa wystawiona publicznie",
  iot: "Urządzenie IoT",
  signature: "Sygnatura własna",
};

export const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  open: "Do analizy",
  in_review: "W analizie",
  confirmed: "Potwierdzone",
  false_positive: "Fałszywy alarm",
  accepted: "Zaakceptowane ryzyko",
};

export const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  queued: "W kolejce",
  running: "W toku",
  paused: "Wstrzymany",
  paused_window: "Czeka na okno",
  completed: "Zakończony",
  cancelled: "Przerwany",
  failed: "Błąd",
};

/** `command`: the tool is a real command line (shown in mono); otherwise it is a plain Polish description. */
export const SCAN_PHASES: { key: ScanPhase; label: string; tool: string; command: boolean }[] = [
  { key: "preflight", label: "Kontrola wstępna", tool: "odsiew martwych adresów", command: false },
  { key: "discovery", label: "Wykrywanie hostów", tool: "nmap -sn / naabu", command: true },
  { key: "services", label: "Porty i usługi", tool: "nmap -sV", command: true },
  { key: "http", label: "HTTP/HTTPS", tool: "httpx, tlsx", command: true },
  { key: "signatures", label: "Sygnatury", tool: "reguły detekcji", command: false },
  { key: "diff", label: "Porównanie", tool: "silnik zmian", command: false },
];

export const DEVICE_LABEL: Record<DeviceType, string> = {
  server: "Serwer",
  workstation: "Stacja robocza",
  printer: "Drukarka",
  camera: "Kamera",
  network: "Urządzenie sieciowe",
  bmc: "Kontroler BMC",
  storage: "Pamięć masowa",
  iot: "Urządzenie IoT",
  unknown: "Nieznany",
};

export const TECH_CATEGORY_LABEL: Record<TechCategory, string> = {
  cms: "CMS",
  framework: "Framework",
  app_server: "Serwer aplikacyjny",
  web_server: "Serwer WWW",
  language: "Język",
  admin_panel: "Panel administracyjny",
  devops: "DevOps",
  database: "Baza danych",
  iot: "IoT",
  network: "Sieć",
  mail: "Poczta",
  other: "Inne",
};

export const CONDITION_TYPE_LABEL: Record<SignatureConditionType, string> = {
  header: "Nagłówek HTTP",
  cookie: "Ciasteczko",
  favicon_hash: "Hash favicony",
  html: "Fragment HTML",
  path: "Ścieżka (GET)",
  title: "Tytuł strony",
  version: "Wersja w treści",
  status: "Kod odpowiedzi",
};

export const CONDITION_OP_LABEL = {
  exists: "istnieje",
  equals: "równa się",
  contains: "zawiera",
  regex: "pasuje do wyrażenia",
} as const;

export const AUDIT_ACTION_LABEL: Record<AuditAction, string> = {
  create: "Utworzenie",
  update: "Edycja",
  delete: "Usunięcie",
  login: "Logowanie",
  logout: "Wylogowanie",
  import: "Import",
  export: "Eksport",
  scan_start: "Start skanowania",
  scan_pause: "Wstrzymanie skanowania",
  scan_resume: "Wznowienie skanowania",
  scan_cancel: "Przerwanie skanowania",
  reveal: "Odsłonięcie danych",
  rotate_key: "Rotacja klucza",
  defectdojo_export: "Wysyłka do DefectDojo",
  recheck: "Ponowny pomiar",
};

export const WEEKDAYS = ["Pn", "Wt", "Śr", "Cz", "Pt", "Sb", "Nd"];
export const WEEKDAYS_LONG = ["Poniedziałek", "Wtorek", "Środa", "Czwartek", "Piątek", "Sobota", "Niedziela"];
