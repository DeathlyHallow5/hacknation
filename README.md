# Attack Surface Intelligence — фронтенд и API-контракт

> HackNation, задание №3 (CBI AGH). Прототип системы циклического discovery-сканирования сетей > 10 000 IP.
> Этот README — **контракт между фронтендом (Next.js) и бэкендом (Rust/axum)**: здесь описан каждый эндпоинт,
> который фронт уже вызывает. Пока Rust-бэкенда нет, все эндпоинты отвечают из встроенного мок-API —
> интерфейс полностью рабочий (редактирование, импорт, живой скан по SSE, RBAC).

- Спецификация проекта: [`PROJECT.md`](PROJECT.md)
- Фронтенд: [`frontend/`](frontend) — Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS 4
- **Единственный источник правды по JSON-формам:** [`frontend/src/lib/api/types.ts`](frontend/src/lib/api/types.ts)
- Все вызовы фронта: [`frontend/src/lib/api/endpoints.ts`](frontend/src/lib/api/endpoints.ts)
- Мок-реализация (эталонное поведение для Rust): [`frontend/src/mock/`](frontend/src/mock)

---

## Содержание

1. [Быстрый старт](#1-быстрый-старт)
2. [Режимы API: mock / proxy / hybrid](#2-режимы-api-mock--proxy--hybrid)
3. [Как подключить Rust (axum) — пошагово](#3-как-подключить-rust-axum--пошагово)
4. [Общие соглашения](#4-общие-соглашения)
5. [Аутентификация и RBAC](#5-аутентификация-и-rbac)
6. [Эндпоинты](#6-эндпоинты) — полный список с правами и примерами
7. [Server-Sent Events: живой прогресс скана](#7-server-sent-events-живой-прогресс-скана)
8. [Форматы импорта и экспорта (CSV/JSON/YAML)](#8-форматы-импорта-и-экспорта)
9. [Правила, которые должен соблюдать бэкенд](#9-правила-которые-должен-соблюдать-бэкенд)
10. [Чек-лист подключения](#10-чек-лист-подключения)
11. [Структура фронтенда и дизайн](#11-структура-фронтенда-и-дизайн)

---

## 1. Быстрый старт

Требования: Node.js ≥ 20.9 (проверено на 24), npm.

```bash
cd frontend
npm install
npm run dev          # http://localhost:3000
```

Проверки качества:

```bash
npm run lint         # ESLint (flat config)
npx tsc --noEmit     # типы
npm run build        # production-сборка
```

### Демо-пользователи (только мок)

Пароль у всех — `demo`. На экране входа есть кнопки «Tryb demonstracyjny», а в меню пользователя — быстрое переключение
ролей (удобно показывать разграничение прав жюри).

| Логин | Имя | Роль | Что может |
|---|---|---|---|
| `jan.kowalski` | Jan Kowalski | Administrator | всё (Administracja) |
| `anna.nowak` | Anna Nowak | Operator | добавление, удаление, изменение (без администрирования) |
| `piotr.wisniewski` | Piotr Wiśniewski | Analityk | изменение и чтение |
| `maria.wojcik` | Maria Wójcik | Obserwator | только чтение и экспорт |
| `audytor` | Audytor zewnętrzny | своя роль | пример пользовательской роли |

Мок-данные детерминированы (одинаковы после перезапуска): сеть кампуса `10.0.0.0/16`, **12 480** активных хостов,
30 ночных сканов, последний дифф #127 → #128, ~1 250 находок, 24 сигнатуры. Правки живут в памяти процесса;
сброс к исходному состоянию — `POST /api/v1/_mock/reset` (нужно право `settings:manage`).

---

## 2. Режимы API: mock / proxy / hybrid

Фронт **всегда** ходит на same-origin `/api/v1/*`. Эти запросы принимает один route handler
[`frontend/src/app/api/v1/[...path]/route.ts`](frontend/src/app/api/v1/%5B...path%5D/route.ts) и в зависимости от
переменной `ASI_API_MODE` (читается **в рантайме**, пересборка не нужна) делает одно из трёх:

| Режим | Что происходит | Когда использовать |
|---|---|---|
| `mock` (по умолчанию) | отвечает встроенный мок из `frontend/src/mock` | дизайн, демо, разработка без бэкенда |
| `proxy` | прозрачный прокси на `ASI_API_URL`: метод, тело, заголовки, cookies (`Set-Cookie`), стрим SSE | бэкенд готов полностью |
| `hybrid` | сначала Rust; если маршрут **не реализован** — ответ из мока | **подключение Rust по одному эндпоинту** |

`hybrid` считает маршрут нереализованным, если Rust вернул **501** или **404 без JSON-тела** (стандартный
fallback axum для неизвестного пути) либо недоступен. «Нормальный» 404 с JSON-ошибкой (`{"error":{...}}`)
пробрасывается как есть.

Каждый ответ содержит заголовок `x-asi-source: mock | upstream`, а в подвале интерфейса видно источник данных.
`GET /api/v1/_meta` отвечает сам диспетчер: `{"mode":"hybrid","upstream":"http://localhost:8080","version":"0.1.0"}`.

Переменные окружения (`frontend/.env.example`):

| Переменная | По умолчанию | Описание |
|---|---|---|
| `ASI_API_MODE` | `mock` | `mock` \| `proxy` \| `hybrid` |
| `ASI_API_URL` | — | адрес Rust-бэкенда, напр. `http://localhost:8080` (в Docker: `http://api:8080`) |
| `ASI_SESSION_COOKIE` | `asi_session` | имя cookie сессии, по которому `proxy.ts` пускает на страницы |
| `ASI_MOCK_LATENCY_MS` | `140` | искусственная задержка мока (видны скелетоны); `0` — без задержки |

Почему прокси, а не прямые запросы браузера в Rust: один origin → **не нужен CORS**, cookie `HttpOnly; SameSite=Lax`
работают как есть, SSE идёт через тот же адрес.

---

## 3. Как подключить Rust (axum) — пошагово

1. Поднимите axum на `:8080` с роутером под префиксом **`/api/v1`**. JSON — `snake_case` (serde по умолчанию для Rust-полей).
2. Запустите фронт в гибридном режиме:
   ```bash
   cd frontend
   ASI_API_MODE=hybrid ASI_API_URL=http://localhost:8080 npm run dev
   ```
   (PowerShell: `$env:ASI_API_MODE="hybrid"; $env:ASI_API_URL="http://localhost:8080"; npm run dev`)
3. Реализуйте эндпоинты в порядке из [чек-листа](#10-чек-лист-подключения). Всё, чего ещё нет в Rust, продолжает
   отвечать мок — интерфейс не ломается.
4. Начните с `POST /auth/login` и `GET /auth/me`: бэкенд должен ставить cookie `asi_session`
   (`HttpOnly; SameSite=Lax; Path=/`) и проверять её на каждом запросе (401 без неё).
5. На каждом эндпоинте проверяйте право из таблиц ниже; при отказе — `403` с полем `required_permission`.
6. Формы ответов сверяйте с [`types.ts`](frontend/src/lib/api/types.ts) — фронт использует их как есть, без маппинга.
7. Когда всё готово — `ASI_API_MODE=proxy`.

Минимальный каркас (axum 0.7/0.8, иллюстрация контракта):

```rust
use axum::{routing::{get, post}, Router, Json, http::StatusCode, response::IntoResponse};
use axum::response::sse::{Sse, Event, KeepAlive};
use serde_json::json;

fn api_error(status: StatusCode, code: &str, message: &str) -> impl IntoResponse {
    (status, Json(json!({ "error": { "code": code, "message": message } })))
}

async fn not_implemented() -> impl IntoResponse {
    // hybrid-режим фронта отдаст этот маршрут мок-у
    api_error(StatusCode::NOT_IMPLEMENTED, "not_implemented", "Endpoint jeszcze nie istnieje")
}

#[tokio::main]
async fn main() {
    let api = Router::new()
        .route("/auth/login", post(login))            // ставит Set-Cookie: asi_session=…
        .route("/auth/me", get(me))
        .route("/dashboard/summary", get(dashboard_summary))
        .route("/scans/{id}/events", get(scan_events)) // SSE, см. раздел 7
        .fallback(not_implemented);
    let app = Router::new().nest("/api/v1", api);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// SSE: события с именем (event:) и JSON в data:
async fn scan_events(/* State, Path(id) */) -> Sse<impl futures::Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = async_stream::stream! {
        // loop { yield Ok(Event::default().event("progress").json_data(json!({"type":"progress","scan": scan})).unwrap()); }
        yield Ok(Event::default().event("done").data(r#"{"type":"done"}"#));
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}
# async fn login() {} async fn me() {} async fn dashboard_summary() {}
```

---

## 4. Общие соглашения

| Тема | Правило |
|---|---|
| Базовый путь | `/api/v1` |
| Формат | JSON, `Content-Type: application/json; charset=utf-8`, ключи в `snake_case` |
| Время | ISO-8601 в UTC (`2026-11-21T04:42:00Z`); фронт показывает в `Europe/Warsaw` |
| Идентификаторы | строки (`"t-1"`, `"scan-128"`, `"h-60424"`, `"s-60424-8080"`, `"f-…"`) |
| Пагинация | запрос: `?page=1&page_size=50` · ответ: `{ "items": [...], "page": 1, "page_size": 50, "total": 12910 }` |
| Сортировка | `?sort=-score,ip` — список полей через запятую, `-` = по убыванию |
| Фильтры-множества | через запятую: `?status=running,paused&change=new,changed` |
| Поиск | `?q=` — регистронезависимая подстрока |
| Файлы (экспорт) | `Content-Disposition: attachment; filename="…"`, тело CSV/JSON/YAML |
| Загрузка файлов | `multipart/form-data`, поле `file` (+ дополнительные поля формы) |
| Тексты ошибок | на польском — фронт показывает `message` пользователю как есть |

### Ошибки

```json
{ "error": { "code": "forbidden", "message": "Twoja rola (Obserwator) nie ma uprawnienia do tej operacji.", "required_permission": "targets:delete" } }
```

| HTTP | `code` | Когда |
|---|---|---|
| 400 | `bad_request` | некорректный запрос |
| 401 | `unauthorized` / `invalid_credentials` | нет сессии / неверный логин (фронт уводит на `/login`) |
| 403 | `forbidden` (+`required_permission`) / `account_disabled` | нет права / аккаунт заблокирован |
| 404 | `not_found` | ресурса нет (обязательно JSON — иначе hybrid уйдёт в мок) |
| 409 | `conflict` | конфликт состояния (встроенная роль, удаление head-скана диффа и т.п.) |
| 422 | `validation` (+`fields: {поле: сообщение}`) | ошибки валидации формы |
| 501 | `not_implemented` | эндпоинт ещё не готов (hybrid → мок) |

---

## 5. Аутентификация и RBAC

- `POST /auth/login` → `Set-Cookie: asi_session=<token>; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`.
- Страницы защищает [`frontend/src/proxy.ts`](frontend/src/proxy.ts) (Next 16 Proxy, бывший middleware): без cookie
  `asi_session` — редирект на `/login`. **Настоящая проверка — на API** (401/403).
- Права имеют вид `resource:action`. Полный список — `PERMISSIONS` в `types.ts`, группы и подписи —
  [`frontend/src/lib/permissions.ts`](frontend/src/lib/permissions.ts).

Четыре встроенные роли (требование 13 задания) + создание своих ролей:

| Роль (UI) | Формулировка задания | Права |
|---|---|---|
| **Administrator** | Administracja | все, включая `users:*`, `roles:*`, `integrations:*`, `audit:read`, `settings:*` |
| **Operator** | Dodawanie, usuwanie, modyfikacja | все `*:read/create/update/delete`, `scans:control`, импорт/экспорт, `assets:recheck`, `findings:defectdojo`, `signatures:test`, `sensitive:reveal` — **без** администрирования |
| **Analityk** | Modyfikacja i odczyt | все `*:read` (кроме админки) + `*:update`, экспорт, `findings:defectdojo`, `signatures:test` — **без** create/delete |
| **Obserwator** | Odczyt | все `*:read` (кроме админки) + экспорт |

UI использует те же права: недоступные кнопки отключены и объясняют причину во всплывающей подсказке,
недоступные разделы показывают «Brak dostępu do tej sekcji».

---

## 6. Эндпоинты

Колонка «Право» — что проверять на бэкенде. `—` = любой вошедший пользователь, `public` = без сессии.
Пути с `{id}` — параметры. Формы тел/ответов — интерфейсы из [`types.ts`](frontend/src/lib/api/types.ts).

### 6.1 Служебные и авторизация

| Метод | Путь | Право | Тело → Ответ | Описание |
|---|---|---|---|---|
| GET | `/_meta` | public | → `ApiMeta` | **отвечает Next-диспетчер**, в Rust не нужен |
| POST | `/_mock/reset` | `settings:manage` | → `{ok:true}` | только мок: пересоздать демо-данные |
| POST | `/auth/login` | public | `LoginRequest` → `Session` + `Set-Cookie` | вход |
| POST | `/auth/logout` | — | → 204 + удаление cookie | выход |
| GET | `/auth/me` | — | → `Session` | текущий пользователь, роль и список прав |

```jsonc
// POST /auth/login
{ "login": "jan.kowalski", "password": "••••" }
// 200
{
  "user": { "id": "u-1", "login": "jan.kowalski", "name": "Jan Kowalski", "email": "jan.kowalski@cbi.uczelnia.example",
            "role_id": "r-1", "role_name": "Administrator", "active": true, "last_login_at": "2026-11-21T13:13:29Z", "created_at": "2026-04-15T13:13:28Z" },
  "role": { "id": "r-1", "key": "admin", "name": "Administrator", "description": "…", "builtin": true, "permissions": ["dashboard:read", "…"], "users_count": 1 },
  "permissions": ["dashboard:read", "targets:read", "…"]
}
```

### 6.2 Pulpit (дашборд)

| Метод | Путь | Право | Ответ | Описание |
|---|---|---|---|---|
| GET | `/dashboard/summary` | `dashboard:read` | `DashboardSummary` | KPI hero: активные хосты + тренд, счётчики изменений, окно, текущий скан |
| GET | `/dashboard/top-findings?limit=10&q=&change=&category=` | `findings:read` | `Finding[]` | самые приоритетные находки (без `false_positive`/`accepted`) |
| GET | `/dashboard/changes-timeline?limit=30` | `changes:read` | `ChangesTimelinePoint[]` | изменения по каждому скану (столбчатая диаграмма) |
| GET | `/dashboard/availability` | `changes:read` | `AvailabilityHeatmap` | доля ответов нестабильных хостов, день недели × час (7×24) |
| GET | `/dashboard/technologies?limit=12` | `assets:read` | `TechStat[]` | самые частые технологии и прирост |
| GET | `/dashboard/address-map?cidr=10.0.0.0/16` | `assets:read` | `AddressMap` | карта адресного пространства (кривая Гильберта на фронте) |

```jsonc
// GET /dashboard/summary (сокращено)
{
  "active_hosts": 12480, "active_hosts_delta": 112,
  "active_trend": [{ "scan_number": 127, "at": "2026-11-20T04:39:00Z", "value": 12368 }, { "scan_number": 128, "at": "…", "value": 12480 }],
  "monitored_addresses": 65536, "targets_count": 14, "services_count": 30213, "web_services_count": 7598,
  "findings_open": 980, "findings_high": 41,
  "changes": { "new": 34, "changed": 19, "gone": 7, "unstable": 12 },
  "changes_base_scan": 127, "changes_head_scan": 128,
  "last_scan": { /* ScanRun */ }, "running_scan": null,
  "window": { "start": "22:00", "end": "06:00", "timezone": "Europe/Warsaw" },
  "window_open": false, "window_progress": 1, "next_window_at": "2026-11-21T21:00:00Z", "rate_limit_rps": 500
}
```

**`AddressMap` — упаковка статусов.** Статус каждого адреса — 4 бита, **в порядке адресов** (не Гильберта — раскладку делает фронт):
байт `i>>1`, старший полубайт — чётный адрес, младший — нечётный; всё в base64. Коды: `0` нет ответа, `1` активный,
`2` новый, `3` изменённый, `4` исчез, `5` нестабильный, `6` неактивный, `7` исключён. Поддерживаются префиксы `/16`…`/24`.

```jsonc
{ "cidr": "10.0.0.0/16", "prefix": 16, "size": 65536, "data": "EREQAAEh…",          // 32 768 байт в base64
  "counts": { "none": 52370, "active": 12304, "new": 30, "changed": 23, "gone": 7, "unstable": 156, "inactive": 390, "excluded": 256 },
  "scan_head": 41230,   // смещение адреса, который сейчас сканируется (null, если скана нет)
  "generated_at": "2026-11-21T13:20:00Z" }
```

### 6.3 Поиск и теги

| Метод | Путь | Право | Ответ | Описание |
|---|---|---|---|---|
| GET | `/search?q=10.0.23` | — | `SearchResult` | палитра Ctrl+K: хосты, цели, находки (≥ 2 символов) |
| GET | `/tags` | — | `TagStat[]` | теги с количеством (подсказки в формах) |

### 6.4 Zakresy (цели сканирования)

| Метод | Путь | Право | Тело → Ответ | Описание |
|---|---|---|---|---|
| GET | `/targets?q=&type=ip,cidr,domain&criticality=&tag=&excluded=&page=&page_size=&sort=` | `targets:read` | → `Paginated<Target>` | список; сортировки: `value`, `name`, `owner`, `type`, `address_count`, `active_hosts`, `criticality_rank`, `updated_at`, `last_scanned_at` |
| GET | `/targets/{id}` | `targets:read` | → `Target` | |
| POST | `/targets` | `targets:create` | `TargetCreateRequest` → `TargetCreateResult` (201) | ручное добавление пачкой; валидация каждого значения |
| PATCH | `/targets/{id}` | `targets:update` | `TargetPatch` → `Target` | правка: `name`, `owner`, `criticality`, `tags`, `notes`, `excluded` |
| DELETE | `/targets/{id}` | `targets:delete` | → 204 | |
| POST | `/targets/bulk` | `targets:update` (+`targets:delete` для `delete`) | `BulkRequest` → `{affected}` | `action`: `tag`, `untag`, `exclude`, `include`, `delete`, `set_owner`, `set_criticality` |
| POST | `/targets/import` | `targets:import` | multipart: `file`, `format?`, `dry_run`, `on_conflict` → `ImportReport` | импорт CSV/JSON; `dry_run=true` — только предпросмотр |
| GET | `/targets/export?format=csv\|json` | `targets:export` | → файл | формат совместим с импортом |

Валидация значения (одинаковая для ручного ввода и импорта — требование 11 задания): IPv4, CIDR (нормализация хост-битов,
максимум `/12`), домен; дубликаты в запросе и в базе. Эталон — `checkTarget()` в [`frontend/src/lib/net.ts`](frontend/src/lib/net.ts).

```jsonc
// POST /targets
{ "items": [{ "value": "10.0.32.0/22", "name": "Pracownia", "owner": "Wydział Informatyki", "criticality": "low", "tags": ["laboratorium"] }],
  "on_conflict": "skip" }               // "skip" | "update"
// 201
{ "created": [ /* Target */ ], "updated": [], "skipped": [{ "value": "10.0.40.66", "reason": "Cel już istnieje" }],
  "errors": [{ "value": "300.1.1.1", "error": "Nieprawidłowy adres IPv4" }] }

// POST /targets/import (dry_run=true) → ImportReport
{ "format": "csv", "dry_run": true, "total_rows": 7, "valid": 5, "invalid": 1, "duplicates": 1, "created": 4, "updated": 1,
  "rows": [{ "row": 2, "value": "10.0.96.0/22", "status": "ok", "type": "cidr", "address_count": 1024 },
           { "row": 7, "value": "300.12.1.1", "status": "invalid", "error": "Nieprawidłowy adres IPv4" }] }
```

### 6.5 Skanowania, профили, расписания

| Метод | Путь | Право | Тело → Ответ | Описание |
|---|---|---|---|---|
| GET | `/scans?status=&source=scanner\|import&q=&page=&page_size=` | `scans:read` | → `Paginated<ScanRun>` | история, новые сверху |
| POST | `/scans/estimate` | `scans:read` | `ScanEstimateRequest` → `ScanEstimate` | **план**: адреса, оценка длительности, разбиение на подгруппы, влезает ли в окно |
| POST | `/scans` | `scans:create` | `ScanCreateRequest` → `ScanRun` (201) | запуск (`start: "now"`) или ожидание окна (`start: "window"` → статус `paused_window`) |
| GET | `/scans/{id}` | `scans:read` | → `ScanRun` | |
| PATCH | `/scans/{id}` | `scans:update` | `ScanPatch` → `ScanRun` | `name`, `notes`, `tags` — **в любом состоянии скана** |
| DELETE | `/scans/{id}` | `scans:delete` | → 204 / 409 | нельзя удалить base/head текущего диффа |
| POST | `/scans/{id}/pause` | `scans:control` | → `ScanRun` | |
| POST | `/scans/{id}/resume` | `scans:control` | → `ScanRun` | в т.ч. «Wznów teraz» для `paused_window` |
| POST | `/scans/{id}/cancel` | `scans:control` | → `ScanRun` | |
| GET | `/scans/{id}/batches` | `scans:read` | → `ScanBatch[]` | подгруппы адресов (сетка на странице скана) |
| GET | `/scans/{id}/logs` | `scans:read` | → `ScanLogLine[]` | журнал фаз/подгрупп/окон |
| GET | `/scans/{id}/events` | `scans:read` | SSE | живой прогресс, см. [раздел 7](#7-server-sent-events-живой-прогресс-скана) |
| GET | `/scans/{id}/export?format=json\|csv` | `scans:export` | → файл | результаты прогона |
| POST | `/scans/import` | `scans:import` | multipart `file` → `ScanRun` (201) | импорт чужих результатов (CSV/JSON) как прогон `source: "import"` |
| GET | `/profiles` | `scans:read` | → `ScanProfile[]` | |
| POST | `/profiles` | `scans:create` | `ScanProfileInput` → `ScanProfile` | `rate_limit_rps` ≤ глобального лимита |
| PATCH | `/profiles/{id}` | `scans:update` | `Partial<ScanProfileInput>` → `ScanProfile` | |
| DELETE | `/profiles/{id}` | `scans:delete` | → 204 / 409 | встроенные и используемые — нельзя |
| GET | `/schedules` | `schedules:read` | → `Schedule[]` | |
| POST | `/schedules` | `schedules:create` | `ScheduleInput` → `Schedule` | окно `HH:MM`, дни ISO 1–7, `frequency: daily\|weekly\|cron` |
| PATCH | `/schedules/{id}` | `schedules:update` | `Partial<ScheduleInput>` → `Schedule` | |
| DELETE | `/schedules/{id}` | `schedules:delete` | → 204 | |

**`next_run_at` считает бэкенд** при создании и каждом изменении расписания: время `Europe/Warsaw`, строго после текущего момента. В моке это `nextScheduleRun` из `frontend/src/lib/schedule.ts`; та же функция показывает в форме превью «Najbliższe uruchomienie», так что правила в Rust должны совпадать:
- `daily` / `weekly` — ближайшее начало окна (`window.start`) в один из дней `days` (ISO: 1 — понедельник … 7 — воскресенье; у `weekly` ровно один день);
- `cron` — ближайшая минута по выражению из 5 полей `минута час день_месяца месяц день_недели`: `*`, списки, диапазоны, шаг `/n`; 0 и 7 — воскресенье. Если ограничены и день месяца, и день недели, достаточно совпадения любого из них (как в Vixie cron). Имена (`MON`, `JAN`) не поддерживаются;
- выключенное расписание → `null`; неверный cron или выражение без срабатываний в ближайший год → `422` с `fields.cron`.

```jsonc
// POST /scans/estimate
{ "target_ids": ["t-1","t-2","t-3","t-4","t-5"], "profile_id": "p-1", "window": { "start": "22:00", "end": "06:00", "timezone": "Europe/Warsaw" } }
// 200
{ "addresses": 65536, "excluded": 0, "est_alive": 12452, "batch_prefix": 22, "batch_size": 1024, "batches": 64,
  "rate_rps": 500, "est_duration_s": 22732, "window_seconds": 28800, "fits_window": true, "windows_needed": 1,
  "notes": ["Podział na 64 podgrup /22 (ok. 6 min każda) — po przekroczeniu okna skan wznowi się od ostatniej ukończonej podgrupy."] }

// POST /scans
{ "name": "Skan doraźny — 21.11.2026", "target_ids": ["t-1"], "profile_id": "p-1", "start": "now",
  "window": { "start": "22:00", "end": "06:00", "timezone": "Europe/Warsaw" },
  "on_window_exceeded": "pause_resume",      // или "stop"
  "test_window_seconds": 25 }                // демо: закрыть окно через N с (можно не поддерживать в Rust)
```

Статусы `ScanRun.status`: `queued`, `running`, `paused`, `paused_window` (ждёт окна / окно закончилось — продолжит
в следующем с контрольной точки), `completed`, `cancelled`, `failed`. Фазы `phase`: `preflight` → `discovery` →
`services` → `http` → `signatures` → `diff`.

### 6.6 Zasoby: хосты и сервисы

| Метод | Путь | Право | Тело → Ответ | Описание |
|---|---|---|---|---|
| GET | `/hosts?q=&availability=&change=&device=&criticality=&tag=&tech=&port=&cidr=&owner=&has_overrides=&include_inactive=&page=&page_size=&sort=` | `assets:read` | → `Paginated<HostSummary>` | сортировки: `ip`, `hostname`, `last_seen`, `first_seen`, `services`, `availability`, `owner`, `score` |
| GET | `/hosts/{id}` | `assets:read` | → `Host` | детали с сервисами и **HTTP-отпечатками** |
| PATCH | `/hosts/{id}` | `assets:update` | `HostPatch` → `Host` | ручная правка → `manual_overrides` |
| DELETE | `/hosts/{id}/overrides/{field}` | `assets:update` | → `Host` | «Przywróć wartość ze skanu» |
| GET | `/hosts/{id}/history` | `assets:read` | → `HostHistoryEntry[]` | история по прогонам |
| POST | `/hosts/{id}/recheck` | `assets:recheck` | → `{queued:true}` (202) | повторный замер (вне ночного окна) |
| GET | `/hosts/unstable?limit=80` | `changes:read` | → `UnstableHost[]` | нестабильные хосты: паттерн ответов, доля по часам |
| GET | `/services?q=&port=&product=&group=&change=&web=true&page=&sort=` | `assets:read` | → `Paginated<ServiceSummary>` | все сервисы |
| GET | `/services/{id}` | `assets:read` | → `Service` | |
| PATCH | `/services/{id}` | `assets:update` | `ServicePatch` → `Service` | исправить product/version (→ `manual_overrides`) |
| POST | `/services/{id}/cookies/{name}/reveal` | `sensitive:reveal` | → `{value}` | раскрыть значение cookie (пишется в аудит) |
| GET | `/service-groups?q=` | `assets:read` | → `ServiceGroup[]` | группировка похожих сервисов + распределение версий |

`HttpFingerprint` (внутри `Service.http`): `url`, `status_code`, `title`, `headers[]` (с `note` для «интересных»),
`cookies[]` (флаги `secure`/`http_only`/`same_site`, **значение только маскированное**), `tls` (CN, issuer, SAN, срок,
`days_left`, протокол, шифр, SHA-256), `redirects[]`, `favicon_hash` (mmh3), `technologies[]` (с `confidence` 0–1 и
списком `sources` — откуда вывод), `environment` (staging/test/dev), `admin_panel`, `body_excerpt`.

### 6.7 Znaleziska (находки)

| Метод | Путь | Право | Тело → Ответ | Описание |
|---|---|---|---|---|
| GET | `/findings?q=&category=&change=&status=&min_score=&tag=&host_id=&ids=&page=&page_size=&sort=` | `findings:read` | → `Paginated<Finding>` | сортировки: `score`, `ip`, `title`, `category`, `status`, `confidence`, `change`, `first_seen`, `last_seen` |
| GET | `/findings/{id}` | `findings:read` | → `Finding` | доказательства, разбор приоритета |
| PATCH | `/findings/{id}` | `findings:update` | `FindingPatch` → `Finding` | `status`, `score_override` (0–100/null), `assignee`, `tags`, `notes` |
| POST | `/findings/bulk` | `findings:update` | `BulkRequest` → `{affected}` | `action`: `set_status`, `tag`, `untag`, `assign` |
| GET | `/findings/export?format=csv\|json&<те же фильтры>&ids=` | `findings:export` | → файл | отчёт |
| POST | `/findings/defectdojo` | `findings:defectdojo` | `DefectDojoExportRequest` → `DefectDojoExportResult` | отправка как Info-finding или evidence |

Категории: `admin_panel`, `staging`, `outdated`, `header`, `cookie`, `tls`, `exposure`, `iot`, `signature`.
Статусы обработки: `open`, `in_review`, `confirmed`, `false_positive`, `accepted`.
`score` — аналитический приоритет 0–100 с разбором `score_breakdown` (фактор → баллы); эталонная формула —
`scoreFinding()` в [`frontend/src/mock/findings.ts`](frontend/src/mock/findings.ts).

```jsonc
// POST /findings/defectdojo
{ "ids": ["f-60436-443-staging"], "as": "finding" }       // "finding" | "evidence"
// 200
{ "exported": 1, "failed": 0, "export_id": "dd-1042",
  "links": [{ "finding_id": "f-60436-443-staging", "url": "https://defectdojo.cbi.uczelnia.example/finding/5042" }] }
```

Маппинг в DefectDojo (`/api/v2/findings/`): `title` → title, `severity` → `Info`, priority → тег, `ip:port` → endpoints,
`evidence[]` → description (или attachment при `as: "evidence"`).

### 6.8 Zmiany (дифф)

| Метод | Путь | Право | Ответ | Описание |
|---|---|---|---|---|
| GET | `/diffs?base=scan-127&head=scan-128&kind=new,changed&q=&min_confidence=0.7&page=&page_size=&sort=` | `changes:read` | `DiffResponse` | сравнение двух прогонов; без параметров — последние два |

```jsonc
{ "base": { "id": "scan-127", "number": 127, "…": "…" }, "head": { "id": "scan-128", "number": 128 },
  "summary": { "new": 34, "changed": 19, "gone": 7, "unstable": 12 },
  "items": [{ "id": "c-128-30", "kind": "changed", "entity": "service", "host_id": "h-60424", "ip": "10.0.236.8",
              "hostname": "staging-api.wydzial-informatyki.uczelnia.example", "port": 8080,
              "summary": "Zmiana wersji Apache Tomcat: 9.0.65 → 9.0.85",
              "fields": [{ "field": "service.8080.version", "label": "Wersja (8080/http)", "before": "9.0.65", "after": "9.0.85" }],
              "confidence": 0.92, "measurements": { "responded": 3, "total": 3 }, "detected_at": "2026-11-21T04:42:00Z" }],
  "page": 1, "page_size": 30, "total": 72 }
```

`kind`: `new` | `changed` | `gone` | `unstable`. `confidence` — уверенность, что изменение реальное, а не шум
нестабильного хоста; `measurements` — сколько из повторных замеров хост ответил.

### 6.9 Sygnatury

| Метод | Путь | Право | Тело → Ответ | Описание |
|---|---|---|---|---|
| GET | `/signatures?q=&source=builtin\|custom&category=&enabled=` | `signatures:read` | → `Signature[]` | |
| GET | `/signatures/{id}` | `signatures:read` | → `Signature` | |
| POST | `/signatures` | `signatures:create` | `SignatureInput` → `Signature` (201) / 422 | проверка безопасности обязательна |
| PATCH | `/signatures/{id}` | `signatures:update` | `Partial<SignatureInput>` → `Signature` | встроенные: только `enabled` |
| DELETE | `/signatures/{id}` | `signatures:delete` | → 204 / 409 | встроенные удалять нельзя |
| POST | `/signatures/test` | `signatures:test` | `SignatureTestRequest` → `SignatureTestResult` | тест на сервисе из инвентаря или на вставленном HTTP-ответе; **без сетевого трафика** |
| POST | `/signatures/import` | `signatures:create` | multipart `file` (YAML/JSON) → `{created, updated, errors[]}` | |
| GET | `/signatures/export?format=yaml\|json` | `signatures:read` | → файл | |

Типы условий: `header`, `cookie`, `favicon_hash`, `html`, `path`, `title`, `version`, `status`;
операторы: `exists`, `equals`, `contains`, `regex`; объединение `and`/`or`.

```jsonc
// SignatureInput
{ "name": "Nagłówek X-Environment: staging", "description": "…", "category": "staging", "technology": null,
  "score_weight": 20, "enabled": true, "tags": ["konwencja-cbi"],
  "match": { "operator": "and", "conditions": [
    { "type": "header", "name": "X-Environment", "op": "equals", "value": "staging" },
    { "type": "path", "path": "/admin/", "op": "exists", "expect_status": 200 } ] } }
```

### 6.10 Administracja

| Метод | Путь | Право | Тело → Ответ | Описание |
|---|---|---|---|---|
| GET | `/users` | `users:read` | → `User[]` | |
| POST | `/users` | `users:manage` | `{login,name,email,role_id,password}` → `User` / 422 | пароль ≥ 12 символов |
| PATCH | `/users/{id}` | `users:manage` | `{name?,email?,role_id?,active?}` → `User` | нельзя снять роль/заблокировать себя (409) |
| DELETE | `/users/{id}` | `users:manage` | → 204 | |
| GET | `/roles` | `roles:read` | → `Role[]` | |
| GET | `/permissions` | `roles:read` | → `Permission[]` | каталог прав |
| POST | `/roles` | `roles:manage` | `{name,description,permissions}` → `Role` | своя роль |
| PATCH | `/roles/{id}` | `roles:manage` | → `Role` / 409 | встроенные менять нельзя |
| DELETE | `/roles/{id}` | `roles:manage` | → 204 / 409 | только без пользователей |
| GET | `/integrations/defectdojo` | `integrations:read` | → `DefectDojoConfig` | токен — только маска |
| PUT | `/integrations/defectdojo` | `integrations:manage` | `DefectDojoConfigInput` → `DefectDojoConfig` | `api_token` хранить зашифрованным |
| POST | `/integrations/defectdojo/test` | `integrations:manage` | → `DefectDojoConfig` (с `last_test`) | |
| GET | `/integrations/defectdojo/exports` | `integrations:read` | → `DefectDojoExport[]` | история отправок |
| GET | `/engines` | `integrations:read` | → `Engine[]` | nmap/naabu/httpx/tlsx/nuclei: версия и статус |
| GET | `/audit?q=&actor=&action=&resource=&from=&to=&page=` | `audit:read` | → `Paginated<AuditEvent>` | журнал «кто/что/когда, было → стало» |
| GET | `/settings` | `settings:read` | → `Settings` | |
| PATCH | `/settings` | `settings:manage` | `Partial<Settings>` → `Settings` / 422 | лимиты сканирования, политика изменений, хранение, окно по умолчанию |
| GET | `/security/encryption` | `settings:read` | → `EncryptionStatus` | Encryption at Rest: алгоритм, ключ, список шифруемых полей |
| POST | `/security/encryption/rotate` | `settings:manage` | → `EncryptionStatus` | ротация ключа |

---

## 7. Server-Sent Events: живой прогресс скана

`GET /api/v1/scans/{id}/events` → `Content-Type: text/event-stream`. Каждое событие имеет имя (`event:`) и JSON в `data:`
(тип `ScanEvent`). Рекомендуемая частота `progress` — 1/с. После `done` сервер закрывает поток.

```text
retry: 3000

event: progress
data: {"type":"progress","scan":{ ...ScanRun... }}

event: batch
data: {"type":"batch","batch":{"id":"scan-129-b7","index":7,"cidr":"10.0.28.0/22","addresses":1024,"status":"done","hosts_alive":402,"duration_s":19,"rate_rps":471,"retries":0, ...}}

event: log
data: {"type":"log","level":"warn","message":"Koniec okna czasowego przy 89% — skan wstrzymany…","at":"2026-11-21T13:38:40Z"}

event: window
data: {"type":"window","state":"paused","resume_at":"2026-11-21T21:00:00Z"}

event: done
data: {"type":"done","scan":{ ...ScanRun... }}
```

Фронт открывает `EventSource` только для «живых» статусов и по `done` обновляет дашборд, карту, дифф и находки.

---

## 8. Форматы импорта и экспорта

Примеры лежат в [`frontend/public/samples/`](frontend/public/samples) и доступны из интерфейса.

**Цели — CSV** (`targets.csv`), заголовок обязателен, `tags` через `|`:

```csv
value,name,owner,criticality,tags,notes,excluded
10.0.96.0/22,Pracownia sieci komputerowych,Wydział Informatyki,low,laboratorium|dydaktyka,,false
10.0.250.0/24,Systemy BMS,Dział Techniczny,critical,bms,Nie skanować,true
```

Синонимы колонок: `value|target|cel|ip|cidr|domain|domena`; `criticality` принимает `low/medium/high/critical`
и `niska/średnia/wysoka/krytyczna`.

**Цели — JSON** (`targets.json`): массив объектов `TargetInput` или `{ "targets": [...] }`.

**Результаты скана — CSV** (`scan-results.csv`): `ip,hostname,port,protocol,service,product,version,title,status_code,observed_at`.

**Результаты скана — JSON** (`scan-results.json`):

```json
{ "scanner": "nmap 7.97", "started_at": "…", "finished_at": "…",
  "hosts": [{ "ip": "10.0.237.50", "hostnames": ["mlflow.lab-ai…"],
              "services": [{ "port": 5000, "protocol": "tcp", "name": "http", "product": "MLflow", "version": "2.11.1" }] }] }
```

**Сигнатуры — YAML/JSON** (`signatures.yaml`): `{ signatures: [SignatureInput, …] }`.

**Экспорт находок** — CSV с колонками `id,title,category,ip,hostname,port,service,technologies,change,status,score,confidence,first_seen,last_seen,assignee,tags,notes`
или JSON `{ generated_at, findings: Finding[] }`.

---

## 9. Правила, которые должен соблюдать бэкенд

**Ручные правки (требование 14).** Поля, изменённые человеком, попадают в `manual_overrides`:

```json
"manual_overrides": { "owner": { "value": "Zespół Projektów Studenckich WI", "scanner_value": "Wydział Informatyki", "by": "Anna Nowak", "at": "2026-11-21T12:02:00Z" } }
```

- Новый скан **никогда не перезаписывает** поле, которое есть в `manual_overrides`; свежее значение сканера пишется в `scanner_value`.
- Править можно в любой момент, в том числе во время скана; правка пишется в аудит.
- `DELETE /hosts/{id}/overrides/{field}` возвращает значение из `scanner_value`.
- Для находок пользовательские поля (`status`, `score_override`, `assignee`, `tags`, `notes`, `defectdojo`) переживают пересчёт находок после скана.

**Нестабильные хосты и неактивность.** Хост становится `inactive` после `settings.change_detection.inactive_after_misses`
(по умолчанию 3) сканов подряд без ответа — запись не удаляется. `response_pattern` — последние 8 замеров (старые слева).
Изменение у нестабильного хоста подтверждается `unstable_retries` повторными замерами; `confidence` ниже
`change_confidence_threshold` = «возможный шум».

**Окна и подгруппы.** Скан делится на подгруппы (`batch_prefix`), чтобы при выходе за окно остановиться на границе
подгруппы, сохранить контрольную точку и продолжить в следующем окне (`on_window_exceeded: "pause_resume"`).

**Безопасность сигнатур** (эталон — `signatureSafety()` в [`frontend/src/mock/handlers/signatures.ts`](frontend/src/mock/handlers/signatures.ts)):
только GET/HEAD; путь начинается с `/`, без `?`-параметров, без `..`, кавычек, `<>`, `;`, SQL-ключевых слов, без параметров
логина/пароля/токена; регулярки должны компилироваться; не более 10 условий. Нарушение → 422.

**Безопасность сканирования.** Глобальные `max_rate_rps`/`max_concurrency` ограничивают любой профиль; адреса из
`excluded_cidrs` и целей с `excluded: true` не сканируются никогда; сканер представляется `User-Agent` из настроек.

**Шифрование в покое.** Шифруются (pgcrypto/AES-256-GCM, ключ из менеджера секретов): HTTP-заголовки, cookies,
сертификаты, фрагменты тела, баннеры, доказательства и заметки, токен DefectDojo, e-mail пользователей
(список отдаёт `GET /security/encryption`). Значения cookie наружу — только маска, полное — через `reveal` с правом и аудитом.

---

## 10. Чек-лист подключения

Порядок подобран так, чтобы интерфейс оживал по частям (в режиме `hybrid` остальное отвечает мок):

- [ ] `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` — cookie `asi_session`, 401/403
- [ ] `GET /dashboard/summary`, `/dashboard/address-map`, `/dashboard/top-findings`, `/dashboard/changes-timeline`, `/dashboard/availability`, `/dashboard/technologies`
- [ ] `GET/POST /targets`, `GET/PATCH/DELETE /targets/{id}`, `POST /targets/bulk`, `POST /targets/import`, `GET /targets/export`
- [ ] `POST /scans/estimate`, `POST /scans`, `GET /scans`, `GET/PATCH/DELETE /scans/{id}`, `pause/resume/cancel`, `GET /scans/{id}/batches`, `GET /scans/{id}/logs`
- [ ] `GET /scans/{id}/events` (SSE)
- [ ] `GET /scans/{id}/export`, `POST /scans/import`
- [ ] `GET/POST/PATCH/DELETE /profiles`, `/schedules`
- [ ] `GET /hosts`, `GET/PATCH /hosts/{id}`, `DELETE /hosts/{id}/overrides/{field}`, `GET /hosts/{id}/history`, `POST /hosts/{id}/recheck`, `GET /hosts/unstable`
- [ ] `GET /services`, `GET/PATCH /services/{id}`, `POST /services/{id}/cookies/{name}/reveal`, `GET /service-groups`
- [ ] `GET /findings`, `GET/PATCH /findings/{id}`, `POST /findings/bulk`, `GET /findings/export`, `POST /findings/defectdojo`
- [ ] `GET /diffs`
- [ ] `GET/POST/PATCH/DELETE /signatures`, `POST /signatures/test`, `POST /signatures/import`, `GET /signatures/export`
- [ ] `GET/POST/PATCH/DELETE /users`, `/roles`, `GET /permissions`
- [ ] `GET/PUT /integrations/defectdojo`, `POST /integrations/defectdojo/test`, `GET /integrations/defectdojo/exports`, `GET /engines`
- [ ] `GET /audit`
- [ ] `GET/PATCH /settings`, `GET /security/encryption`, `POST /security/encryption/rotate`
- [ ] `GET /search`, `GET /tags`
- [ ] Переключить `ASI_API_MODE=proxy`

---

## 11. Структура фронтенда и дизайн

```
frontend/
  .env.example                      переменные режима API
  public/samples/                   примеры CSV/JSON/YAML для импорта
  src/
    proxy.ts                        защита страниц (cookie asi_session)
    app/
      api/v1/[...path]/route.ts     диспетчер mock | proxy | hybrid
      (app)/                        разделы приложения (Pulpit, Znaleziska, Zmiany, Zasoby, Skanowania, Zakresy, Sygnatury, Administracja)
      login/, dostepnosc/           вход и декларация доступности
    components/
      ui/                           примитивы (Radix + Tailwind): кнопки, формы, диалоги, панели, табы, Ctrl+K
      layout/                       двухуровневая шапка, меню, палитра команд, подвал
      data/                         таблица с серверной пагинацией, статусы, шкалы приоритета и уверенности
      edit/                         мастер импорта CSV/JSON
      viz/                          карта Гильберта, sparkline, стек изменений, тепловая карта, сетка подгрупп
      rbac/                         проверка доступа к разделам
    features/<раздел>/              экраны и формы
    lib/
      api/types.ts                  КОНТРАКТ API
      api/endpoints.ts, client.ts   вызовы и обработка ошибок
      permissions.ts, labels.ts     роли, права, польские подписи
      net.ts, format.ts             IP/CIDR/кривая Гильберта, форматирование pl-PL
    mock/                           мок-бэкенд: seed, роутер с RBAC, обработчики, симуляция скана
```

**Интерфейс — только на польском** (пользователи — государственные учреждения Польши).

**Дизайн-система** (токены в [`frontend/src/app/globals.css`](frontend/src/app/globals.css)):

- «Институциональный SOC»: гранатовая шапка и hero (`#0B1830`), светлая рабочая зона (`#F2F5F9`).
  Циан `#1EB2EA` — только действия, фокус и прогресс; цвета статусов — только статусы изменений
  (Nowy / Zmieniony / Zniknął / Niestabilny / Nieaktywny), всегда с иконкой и текстом.
- Палитры графиков проверены валидатором (разделимость для дальтоников, контраст); для тёмной темы — свои шаги.
  На карте адресов изменения помечены ещё и формой (+ ◆ ×), а не только цветом.
- Шрифты **Atkinson Hyperlegible Next / Mono** — созданы для различимости 0/O и 1/l/I (важно для IP и хешей) и для доступности.
- Три темы (светлая как в макете, тёмная, высокий контраст) и размер текста A / A+ / A++ — меню «A+» в шапке;
  ограничение анимаций; skip-link; клавиатура; «Deklaracja dostępności» (WCAG 2.1 AA).
- Герб Польши из макета не используется (его применение ограничено законом) — свой знак; для официальных логотипов
  предусмотрена папка `frontend/public/brand/`.
