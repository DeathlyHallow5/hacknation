# HANDOFF — где остановились и как продолжить

> Снимок на **2026-11-21**. Один файл со всем контекстом, чтобы продолжить разработку на другом ПК — вручную или с Claude Code (его локальная память на новый ПК **не переезжает**, поэтому всё нужное записано здесь).
> Рядом: `PROJECT.md` — спецификация v0.3; `docs/ASI_Architecture_Security_Roadmap_v2.md` — внешнее ревью (находки F-01…F-27, тесты T-01…T-20); `README.md` — запуск и API; `docs/task3-attack-surface-intelligence.pdf` — задание AGH.

> **Обновление 2026-11-21, вечер:** §8.1 (авторизация/RBAC/аудит/правки) доделан и влит в `dev`;
> фронтенд из ветки `vovan` влит в `frontend/` и подключён к ядру через `/api/v1` (`core/src/v1.rs`);
> `a97eaa0` проверен на лабе (`diff-demo.sh`, T-12). Актуальное состояние — **`docs/STATUS.md`**,
> разделы ниже про §8.1 описывают историю. T-07…T-10 и бенчмарк 10k ещё не прогнаны.

---

## 0. Точка остановки

| Что | Где | Состояние |
|---|---|---|
| Основная ветка разработки | `dev` @ `a97eaa0` + коммит с этим файлом | собирается, **27 unit-тестов зелёные**, clippy без замечаний (кроме dead-code в `rbac.rs`, уйдёт с RBAC) |
| Фиксы из ревью (14 находок) | коммит `a97eaa0` | в коде и в unit-тестах есть, **на лабе ещё не проверены** → первый шаг (§6) |
| Авторизация, RBAC, аудит, правки (overlays) | ветка **`wip/auth-rbac-overlays`** | сделано ~40% (§8.1): миграции, таблица прав, конфиг, аудит, хендлеры правок; **не подключено к API**, `auth.rs` не написан |
| Кастомные сигнатуры + импорт/экспорт JSON/CSV | — | не начато (агент остановлен до первых изменений), ТЗ готово (§9.2) |
| `main` | `de637f6` | только документация (PROJECT.md v0.3 + ревью). Код в `main` не заливали |

**Порядок продолжения:** поднять окружение (§3) → проверить `a97eaa0` на лабе (§6) → доделать `wip/auth-rbac-overlays` (§8.1 + ТЗ §9.1) и параллельно сигнатуры + импорт/экспорт (ТЗ §9.2) → интеграция (§9.3) → раунд 2 (§10).

---

## 1. Проект

- **HackNation 2026**, задание №3 **«Attack Surface Intelligence»**, заказчик — Centrum Bezpieczeństwa Informacji AGH (Краков), приз 25 000 PLN.
- Суть: циклическое discovery-сканирование больших сетей (>10 000 IP) — хосты, сервисы, HTTP/TLS-fingerprint, CMS/админки/staging/IoT, **сравнение прогонов** (new/gone/changed, нестабильные хосты), кастомные сигнатуры без эксплуатации, **4 роли RBAC**, **правки с сохранением между сканами**, шифрование чувствительных полей, импорт/экспорт JSON/CSV, окна по времени и частота, ограничение темпа, DefectDojo (желательно). Сдача: репозиторий, документация, ≤10 слайдов с живым демо; AGH тестирует ≥2 прогона в своей лаборатории.
- Веса оценки: discovery 30% · изменения/нестабильность/отчётность 15% · инженерное качество/доки/импорт-экспорт/DefectDojo 20% · безопасность сканирования/дашборд 15% · fingerprint/сигнатуры 10% · роли/защита данных 10%.
- **Команда — 3 человека.** Мы (владелец репозитория + Claude) — бэкенд: Rust-ядро, БД, планировщик, дифф, RBAC, интеграции. Фронтенд делает участник команды в своём проекте (`hacknation-vovan`, Next.js, ходит в `/api/v1/...`, по умолчанию на моках). `web/` в этом репо — UI из SWOT с прокси `/api` на ядро.
- Репозиторий: `github.com/DeathlyHallow5/hacknation` (приватный). Основа — форк SWOT (GPL-3.0) → весь проект под GPL-3.0.

## 2. Правила работы (обязательны и для людей, и для ассистента)

1. Вся работа — в ветку **`dev`**. В **`main` — только по явной команде владельца репозитория.** WIP-ветки `wip/*` допустимы для незаконченного.
2. **`.env` никогда не коммитить** (там `ASI_DATA_KEY`, пароли). В репо только `.env.example`.
3. Личные данные владельца (email и т.п.) не отправлять во внешние сервисы.
4. Коммиты, написанные Claude, заканчиваются строкой `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
5. Сканировать только свою lab (`172.30.0.0/24`) или явно разрешённые диапазоны. Для API-тестов без сканов: создавать сканы с `"start": false`; режим «ядро без планировщика» (`ASI_MAX_RUNS=0`) появится вместе с `config.rs` из `wip/auth-rbac-overlays` — на `dev` значение 0 сейчас игнорируется (становится 2).
6. Не править уже применённые миграции (sqlx проверяет checksum) — только новые файлы. Номера зарезервированы: **0006–0009** — auth/overlays, **0010–0019** — сигнатуры/импорт.
7. Фронтенд — зона участника команды; общий контракт API (OpenAPI, `/api/v1`) ещё не согласован (F-17/F-18).

## 3. Перенос на новый ПК — чеклист

**Что ставить** (версии на старом ПК): git, `gh` 2.102 (`gh auth login`), Docker 29 + Compose v2 (5.5), Rust **stable ≥ 1.85** (edition 2024; было 1.98), Node 26 + npm 12 (только для `web/` без Docker), Python 3 (установщик сканеров), openssl.
Старый ПК: 4 ядра / 7.6 ГБ — две параллельные сборки Rust шли очень медленно; на мощном ПК параллельные агенты в отдельных worktree нормальны (у каждого свой `core/target`, первая сборка — несколько минут).

```bash
git clone https://github.com/DeathlyHallow5/hacknation.git && cd hacknation
git checkout dev
git fetch origin wip/auth-rbac-overlays          # незаконченная авторизация (§8.1)

cp .env.example .env
sed -i "s|^ASI_DATA_KEY=.*|ASI_DATA_KEY=$(openssl rand -base64 32)|" .env
# после влития авторизации добавить в .env: ASI_ADMIN_PASSWORD=<≥12 символов>

docker compose --profile lab up --build -d      # db + core + web + lab (nginx .10, httpd .11)
curl -s localhost:8000/api/health               # {"status":"ok"}; UI — http://localhost:3000
cd core && cargo test                           # 27 passed
```

- **Данные БД со старого ПК не переносятся** (docker volume `asi_db-data`) — и не нужно: lab воспроизводима, на новом ПК — новая БД и новый `ASI_DATA_KEY`. Если всё же нужны старые прогоны — `pg_dump` + тот же `ASI_DATA_KEY` (без ключа зашифрованные поля не прочитать).
- Сканеры есть внутри образа `core` (Dockerfile ставит pinned naabu/httpx/tlsx/nuclei с проверкой SHA-256 + nmap из Debian). Для `cargo run` со сканами на хосте: `nmap` из пакетов + `python3 tools/install_tools.py --dest tools/bin --only naabu httpx tlsx nuclei` и `ASI_TOOLS_DIR=$PWD/tools/bin` (`tools/bin` в `.gitignore`).
- Локальная разработка без Docker — команды в README («Разработка без Docker»).

## 4. Архитектура и карта кода

**Стек:** Rust (axum 0.8 — пути `/{id}`; tokio; sqlx 0.9 — runtime-запросы, `sqlx::AssertSqlSafe` только для константных фрагментов) · PostgreSQL 17 + pgcrypto (`pgp_sym_encrypt/decrypt`, ключ `ASI_DATA_KEY` из env) · сканеры — подпроцессы, цели передаются файлом-списком (без shell) · Next.js (`web/`) · Docker Compose.

| Модуль `core/src` | Что делает |
|---|---|
| `main.rs` | конфиг → пул PG (16) → миграции → `scheduler::run` → axum |
| `config.rs` | env: `DATABASE_URL`, `ASI_BIND` (0.0.0.0:8000), `ASI_DATA_KEY`, `ASI_TOOLS_DIR` (/opt/asi-tools), `ASI_MAX_CONCURRENCY` (256, потоки naabu/httpx ≤100), `ASI_MAX_RUNS` (2), `DEFECTDOJO_URL/TOKEN` |
| `input.rs` | нормализация IP/CIDR/доменов; лимиты: IPv4 ≥/8, IPv6 ≥/104, ≤2²⁴ адресов на скан; текст/CSV (1-я колонка, кавычки); срез n-го батча арифметикой O(1); `contains` для покрытия |
| `engine.rs` | `Tool` (nmap, naabu, `pd-httpx`, tlsx, nuclei), поиск в `ASI_TOOLS_DIR`/PATH, запуск с таймаутом, kill_on_drop, **stdout ≤ 64 MiB** |
| `parse.rs` | nmap XML (`-sn` живые, `-sV` сервисы + conf), naabu JSONL, httpx JSONL |
| `fingerprint.rs` | CMS по списку, admin/staging эвристики (R-03: admin ищется подстрокой в URL) |
| `pipeline.rs` | `execute_run`: снимок целей и **настроек** прогона, чекпоинт-смещение, окна, адаптивный батч, ETA, **повтор батча ×1 → `failed_ranges` → статус `partial`**, отмена. `run_batch`: pre-flight (`nmap -sn`, только добавляет живых) → `naabu` по всем входам → `nmap -sT -sV` по открытым → `httpx` (без `-fr`) → запись в одной транзакции, чувствительное шифруется |
| `history.rs` | финализация: повторная проверка пропавших (через 10 с), перенос пропавших хостов (unstable → inactive), **покрытие (`Coverage`)**, дифф → `diffs` (зашифрован), сравнение любых двух прогонов |
| `diff.rs` | чистый дифф host/service/http с множеством `skip` (несопоставимые адреса), confidence, interest 1–3 |
| `scheduler.rs` | опрос каждые 5 с: восстановление `running→paused` при старте, захват `paused`/due-сканов (`SKIP LOCKED`), семафор `ASI_MAX_RUNS`, паника в прогоне → `failed`, `cancelled` не перезаписывается |
| `api.rs` | REST (таблица ниже) |
| `rbac.rs` | роли/действия — на `dev` пока не используются |

**Миграции:** 0001 схема (users, targets, scans, hosts, services, http_findings, signatures, signature_hits, diffs, tags, audit_log) · 0002 `scan_runs` (описание скана ≠ прогон) · 0003 `run_artifacts` (сырые выводы сканеров по батчам, зашифрованы — для DefectDojo) · 0004 дифф (inactive_after_misses, flaps, interest, old/new_enc) · 0005 целостность (статус `partial`, чекпоинт BIGINT, `config_snapshot`).

**API на `dev`** (`/api/...`, без авторизации!):

| Метод | Путь | Примечание |
|---|---|---|
| GET | `/health`, `/tools` | |
| GET/POST | `/targets` | текст/CSV |
| GET/POST | `/scans` | `start:false` — сохранить без запуска; >2²⁴ адресов → 422 |
| POST | `/scans/{id}/run` | **409**, если у скана уже есть активный прогон |
| GET | `/scans/{id}/runs` | |
| GET | `/runs/{id}` | статус: queued/running/paused/done/**partial**/failed/cancelled; stats: прогресс, ETA, `failed_ranges`, `hosts_failed`, `analysis` (baseline/complete/failed), `diff` |
| GET | `/runs/{id}/findings` | хосты → сервисы → HTTP (расшифровано, без пагинации) |
| GET | `/runs/{id}/diff[?against=<run>]` | summary + `not_comparable`; неизвестный `against` → 404 |
| POST | `/runs/{id}/cancel` | |

**Lab:** сеть `172.30.0.0/24` (internal): `.10` nginx, `.11` httpd (профиль `lab`), `.12` «Admin login - staging» (профиль `lab2`), core в сети как `.2`, шлюз `.1`. Скрипты: `scripts/lab-scan.sh` (один скан), `scripts/diff-demo.sh` (4 прогона с изменениями + сравнение 1 vs 4, ~2.5 мин).

## 5. Что сделано (история `dev`)

| Коммит | Что |
|---|---|
| `da2ca42` | PROJECT.md v1 (в `main`) |
| `f68cdd2` | скелет монорепо: Rust core, схема Postgres, web из SWOT, Compose |
| `f344fe3` | Pipeline A: discovery по расписанию, окна, rate limit, батчи, ETA, recovery, cancel |
| `fb28ddb` | Diff Engine: повторная проверка, unstable/inactive, flaps, confidence, interest, шифрование диффов |
| `6adea36`, `de637f6` | PROJECT.md v0.3 + внешнее ревью v2 (в `main` и `dev`) |
| `a97eaa0` | **фиксы целостности из ревью** (§7) |

## 6. Проверено и что проверить первым

**Проверено на lab до `a97eaa0`:** discovery (nginx 1.27.5 / Apache 2.4.71, conf 1.0); шифрование (в дампе 0 строк открытого текста в зашифрованных полях, сырые артефакты расшифровываются); окно с паузой и продолжением в 3 окнах; отмена; 4-прогонный дифф (новая админка — interest 3, unstable 0.5 → inactive 1.0, «reappeared» с flap 0.5, run 1 vs run 4 — только админка).

**Проверить для `a97eaa0` (ещё не делали):**
1. `docker compose --profile lab up --build -d` → миграция 0005 применилась, `/api/health` ок.
2. `scripts/diff-demo.sh` → результаты как раньше, в summary `not_comparable: 0`, все прогоны `done`, `analysis` = `baseline`/`complete`.
3. **T-07 сбой батча:** во время прогона `docker compose exec -u root core mv /opt/asi-tools/naabu /opt/asi-tools/naabu.off` (вернуть после) → батч повторён и записан в `failed_ranges`, прогон `partial`, в диффе нет ложных `gone`, следующий прогон сравнивается с последним `done`.
4. **T-08 цель убрана:** `docker compose exec db psql -U asi asi` → заменить цели скана в `scan_targets` на более узкие → новый прогон: убранные адреса в `not_comparable`, не `gone`.
5. **T-09 дрейф настроек:** скан с окном; между окнами `UPDATE scans SET ports='22'` → продолжение идёт с портами из `config_snapshot`.
6. **T-10 отмена:** `POST /runs/{id}/cancel` во время финализации (10-секундная пауза перед повторной проверкой) → статус остаётся `cancelled`, `finished_at` заполнен.
7. **T-12 лимиты:** `10.0.0.0/7`, `fd00::/64` → 422; `POST /scans/{id}/run` при активном прогоне → 409.
8. Pre-flight больше не отсекает адреса → naabu сканирует все входы: на больших разреженных диапазонах это медленнее — замерить в бенчмарке 10k.

После проверки обновить статусы в `PROJECT.md` §15 (там пока все находки «открыты»).

## 7. Реестр находок — статус после `a97eaa0`

- **Исправлено в коде (ждёт проверки на lab):** F-03 (httpx без `-fr`), F-04 (повтор батча, `partial`, не база для диффа), F-05 (покрытие: `not_comparable` вместо `gone`), F-06 (pre-flight не фильтрует), F-07 (`config_snapshot`), F-09 (`cancelled` окончателен), F-10 (лимит stdout), F-12 (BIGINT, O(1)-срез, IPv6 ≥/104, ≤2²⁴), F-21 (`stats.analysis`), F-24 (O(n) дедуп), R-01 (отмена во время финализации), R-02 (паника → `failed`), R-05 (CSV в кавычках), R-06 (409/404).
- **В работе (`wip/auth-rbac-overlays`):** F-01 (auth), F-14 (права на evidence), F-15 (правки), частично F-13 (заметки шифруются).
- **ТЗ готово, не начато:** F-16 (импорт JSON/результатов), F-26 (сигнатуры) + экспорт JSON/CSV.
- **Открыто:** F-02 scope-политика · F-08 lease/heartbeat (в MVP один экземпляр core) · F-11 глобальный бюджет pps · F-13 классификация полей · F-17/F-18 контракт с фронтом · F-19 пагинация · F-20 окна по часам · F-22 счёт битых строк парсеров · F-23 полные `Set-Cookie` · F-25 tmp-файлы · F-27 образы без digest / дефолтный пароль БД · R-03 admin-эвристика · R-04 домен с несколькими IP.

## 8. Незавершённая работа

### 8.1 `wip/auth-rbac-overlays` (остановлен на середине)

Ветка от `a97eaa0`, один WIP-коммит `58a17eb` (`git fetch origin wip/auth-rbac-overlays`). **Готово:**
- `core/migrations/0006_auth.sql` — `users`: `disabled`, `can_execute_scans` (CHECK: viewer не может), `updated_at`, `last_login_at`; таблица `sessions` (только SHA-256 токена, ip, expires/last_seen/revoked); `audit_log`: ip, method, path (шаблон маршрута), status, outcome; триггеры append-only (UPDATE/DELETE/TRUNCATE запрещены).
- `core/migrations/0007_annotations.sql` — `annotations` (scan-level overlay по ключам диффа: host → IP, service → `ip:port/proto`, http → URL; label, owner, tags, priority 1–3, false_positive, suppressed + reason, `notes_enc`, `version` для optimistic locking; UNIQUE(scan, kind, key)); `annotation_history` (append-only, удаляется только каскадом со сканом); `targets.notes_enc`.
- `core/src/config.rs` — `ASI_SESSION_TTL_HOURS` (12), `ASI_COOKIE_SECURE`, `ASI_ADMIN_USER` (admin), `ASI_ADMIN_PASSWORD`; `ASI_MAX_RUNS=0` = только API; `Debug` скрывает секреты; `Config::for_tests()`.
- `core/src/rbac.rs` — действия `Read, ReadEvidence, Create, Update, Delete, ExecuteScan, ManageUsers, ManageIntegrations, ReadAudit`; `can(role, can_execute_scans)`; **таблица прав `ROUTES`** (метод + шаблон пути → Public / Authenticated / Requires(Action)) для всех текущих и планируемых маршрутов; тесты полной матрицы.
- `core/src/audit.rs` — запись событий, `Note` (хендлер описывает действие для строки аудита), `GET /api/audit` с курсором.
- `core/src/overlay.rs` — хендлеры list/put (с проверкой версии → 409)/delete/history, канонизация ключей, `Overlay` для наложения на findings/diff.

**Не сделано:** `core/src/auth.rs` (login/logout/me, Argon2id, сессии, cookie + `X-ASI-CSRF`, лимитер входа, бутстрап админа, middleware `gate` с deny-by-default через `rbac::rule`), users API, подключение в `api.rs` (`route_layer` в конце `router()`, `pub` для `internal`/`ApiResult`, редакция evidence для Viewer, наложение overlay в findings/diff + `?hide_suppressed`, PATCH/DELETE для targets и scans), `main.rs` (mod-строки, `into_make_service_with_connect_info`, бутстрап), зависимости в `Cargo.toml` (argon2, sha2, rand, base64), `.env.example`/compose (`ASI_ADMIN_*`), интеграционные тесты.
**Сборка:** `cargo check --all-targets` проходит (7 предупреждений dead-code: новые типы `rbac` ещё нигде не вызываются); unit-тесты WIP не запускались. `audit.rs` и `overlay.rs` ещё **не объявлены в `main.rs`** и не компилировались: они используют `crate::api::{bad, internal, not_found, ApiError, ApiResult}` (в `api.rs` сделать `pub(crate)`) и `crate::auth::CurrentUser` (модуля `auth` пока нет) — при подключении ожидать ошибок компиляции.
Полное ТЗ — §9.1.

### 8.2 Сигнатуры + импорт/экспорт

Изменений нет — агент успел только прочитать код. Начинать с ТЗ §9.2 от `dev` (или от `dev` после влития §8.1).

## 9. Полные ТЗ (как ставились агентам; годятся для перезапуска)

Общие условия для обоих потоков: работа в отдельном git worktree/ветке от `dev`; коммиты с `Co-Authored-By`; без push в `dev`/`main` до интеграции; **не трогать рабочий стек Docker** — для интеграционных проверок свой одноразовый Postgres: `docker run -d --rm --name asi-test-pg-<x> -e POSTGRES_USER=asi -e POSTGRES_PASSWORD=asi -e POSTGRES_DB=asi -p 127.0.0.1:<5543x>:5432 postgres:17-alpine` и `DATABASE_URL=postgres://asi:asi@127.0.0.1:<port>/asi ASI_DATA_KEY=test-only ASI_BIND=127.0.0.1:<1808x> ASI_MAX_RUNS=0 cargo run`; сканы только с `"start": false`; `cargo build && cargo test && cargo clippy --all-targets` без новых предупреждений. В отчёте: ветка, коммиты, миграции, таблица маршрутов с правами, env, результаты тестов, ограничения.

### 9.1 Поток «API и безопасность»: auth + RBAC + аудит + правки

**Файлы потока:** `api.rs`, `rbac.rs`, `config.rs`, `main.rs`, новые `auth.rs`/`audit.rs`/`overlay.rs`, `Cargo.toml/lock`, миграции 0006–0009, `.env.example`, `compose.yaml` (только env сервиса `core`). **Не трогать:** `pipeline.rs`, `history.rs`, `diff.rs`, `engine.rs`, `parse.rs`, `fingerprint.rs`, `scheduler.rs`, `input.rs`, `web/`, документацию. Не менять обработку `POSTGRES_PASSWORD`.

**A. Аутентификация и авторизация (F-01, F-14; тесты T-01, T-02)**
1. Миграция 0006 (готова, §8.1). Пользователей не удаляем — отключаем.
2. Пароли: Argon2id, длина 12–256; для неизвестного логина всё равно проверка по фиктивному хэшу (без перебора логинов по времени); ответ «invalid credentials».
3. Сессии: 32 случайных байта (OS RNG), base64url; в БД только SHA-256; TTL `ASI_SESSION_TTL_HOURS`; logout отзывает; отключение пользователя / смена роли или пароля отзывают его сессии. Принимать `Authorization: Bearer` **и** cookie `asi_session` (HttpOnly; SameSite=Strict; Path=/api; Secure при `ASI_COOKIE_SECURE=true`). Токен в query string — никогда. **CSRF:** для cookie-запросов с небезопасными методами нужен заголовок `X-ASI-CSRF: 1`, иначе 403; Bearer — без этого требования.
4. Deny-by-default: одна middleware через `route_layer` **в самом конце** `api::router()` (после всех `.route()`/`.merge()`), чтобы закрыть и маршруты, добавленные другими модулями. Публичные — только `GET /api/health`, `POST /api/auth/login`. Права — по `rbac::ROUTES` (метод + `MatchedPath`); маршрут вне таблицы — только Admin + `warn!`. В extensions кладётся `CurrentUser { id, username, role, can_execute_scans }`. Ответы: 401 `{"detail":"authentication required"}`, 403 `{"detail":"forbidden"}`.
5. Матрица: Admin — всё; Editor — Read, ReadEvidence, Create, Update, Delete (+ExecuteScan по флагу); Modifier — Read, ReadEvidence, Update (+ExecuteScan по флагу); Viewer — только Read (флаг всегда false). Флаг по умолчанию: admin/editor — true, остальные — false. `POST /scans` со `start: true` требует ещё и ExecuteScan. `/runs/{id}/findings`: без ReadEvidence не расшифровывать banner/headers/cookies/tls (select NULL) и вернуть `"redacted": true`.
6. API: `POST /api/auth/login {username,password}` → `{token, expires_at, user}` + Set-Cookie; `POST /api/auth/logout`; `GET /api/auth/me`; admin: `GET/POST /api/users`, `PATCH /api/users/{id} {role?,password?,disabled?,can_execute_scans?}`, `DELETE /api/users/{id}` (= отключить). Нельзя отключить/понизить последнего активного админа; нельзя менять себе роль. Валидация логинов.
7. Ограничение входа: в памяти (AppState) — 5 неудач на логин или 20 на IP за 15 мин → 429 до конца окна (`ConnectInfo<SocketAddr>`, сервер через `into_make_service_with_connect_info::<SocketAddr>()`).
8. Бутстрап: если нет активного админа — создать из `ASI_ADMIN_USER` + `ASI_ADMIN_PASSWORD` (≥12), иначе завершиться с понятной ошибкой. Пароли и токены не логировать. Переменные — в `.env.example` и в env `core` в compose.
9. Аудит (append-only): вход ок/неудача, выход, изменения пользователей, каждый изменяющий запрос (метод, шаблон пути, параметры пути, статус, пользователь), каждый 401/403 на защищённом маршруте — пишется в middleware после ответа. Без паролей, токенов и тел запросов. `GET /api/audit?limit=&before=` (ReadAudit; limit ≤ 500, по умолчанию 100).

**B. Правки, которые переживают пересканирование (F-15, AGH п.14, тест T-14)**
1. Миграция 0007 (готова, §8.1): overlay на уровне скана по ключам диффа; сырые данные неизменны.
2. API: `GET /api/scans/{id}/annotations` (Read, фильтр по kind); `PUT /api/scans/{id}/annotations` (Update; `version` отсутствует/0 — создать; не совпала — 409 с текущей записью); `DELETE /api/scans/{id}/annotations/{annotation_id}` (Delete); `GET .../{annotation_id}/history` (Read). Правки работают при любом статусе прогона, в том числе во время скана.
3. Наложение при чтении: findings — к каждому host/service/http; diff — к записям по `entity`, плюс `?hide_suppressed=true`.
4. Правка конфигурации и данных: `PATCH /api/targets/{id} {label?, notes?}` (Update; `manual_edit=true`), `DELETE /api/targets/{id}` (Delete), `PATCH /api/scans/{id}` (Update; те же проверки, что при создании; действует со следующего прогона благодаря `config_snapshot`), `DELETE /api/scans/{id}` (Delete; 409 при активном прогоне).

**Проверка:** curl — каждый непубличный маршрут без авторизации → 401; матрица ролей × маршрутов (viewer не создаёт/не меняет/не запускает; modifier не создаёт/не удаляет; editor не управляет пользователями и не запускает без флага); cookie без `X-ASI-CSRF` на POST → 403; блокировка входа → 429; строки аудита пишутся, `UPDATE audit_log` падает; viewer получает `redacted`; правка → конфликт версий 409 → правка видна в findings двух разных прогонов одного скана.

### 9.2 Поток «данные и движок»: сигнатуры + импорт/экспорт

**Файлы потока:** новые `signatures.rs`, `transfer.rs` (или `import.rs`/`export.rs`), данные `core/signatures/*.json`, `core/fixtures/*`, `pipeline.rs`, `history.rs`, `diff.rs`, `parse.rs`, `fingerprint.rs`, `Cargo.toml/lock`, миграции 0010–0019. В `main.rs` — только `mod`-строки; в `api.rs` — только по одной строке `.merge(crate::<module>::routes())` перед `.with_state(state)` (модуль отдаёт `pub fn routes() -> Router<AppState>`). **Не трогать:** `rbac.rs`, `config.rs`, `scheduler.rs`, `engine.rs`, `input.rs` (вызывать можно), остальной `api.rs`/`main.rs` (без новых полей AppState), compose, `.env*`, `web/`, документацию. Авторизацию не делать (её даёт поток 9.1); для каждого маршрута указать нужное право; `created_by` оставлять NULL.

**A. Кастомные сигнатуры (AGH п.10, помогает п.6–7; F-26; тест T-20)**
1. **Только декларативный JSON** (без YAML, кода, URL, команд): `{ "id", "version", "name", "description", "category": "admin|cms|framework|app_server|iot|staging|other", "confidence": 0–1, "tags": [], "condition": "any|all", "matchers": [...], "enabled": true }`. Типы matcher'ов — по уже собранным данным: `title` (regex), `header` (имя + regex значения), `cookie_name`, `favicon` (hash), `tech` (regex по списку технологий httpx), `status` (коды), `tls` (поле + regex: CN subject/issuer, SAN…), `service` (порт + regex по service/product/version/cpe из nmap). **Сигнатуры не создают сетевых запросов.**
2. Безопасность: crate `regex` (линейное время) с лимитами `RegexBuilder`; шаблон ≤ 512 символов; ≤ 20 matcher'ов; значения обрезаются (~4 KiB) до сопоставления; `deny_unknown_fields`; правило ≤ 64 KiB; компиляция при create/update → 422 с причиной. Unit-тесты: огромный regex, слишком много matcher'ов, лишнее поле (`"command"`, `"url"`) — отклоняются.
3. Хранение (миграция 0010): доработать `signatures` (version, category, confidence, builtin, updated_at; снять старый CHECK по `kind`) и `signature_hits` (по прогону через service_id; URL для HTTP; версия сигнатуры; confidence; время; `evidence_enc` — зашифрованный JSON совпавших полей).
4. Встроенный набор ~15–25 сигнатур (`include_str!`, upsert при старте по id+version — функцию вызвать из `main.rs` при интеграции): админки (phpMyAdmin, Grafana, Kibana, Jenkins, GitLab, Portainer, Webmin, Tomcat Manager, Plesk/cPanel), серверы приложений (Tomcat, IIS, JBoss/WildFly, WebLogic), IoT/встроенные веб-серверы (камеры, роутеры, принтеры — известные Server-заголовки/title), признаки staging/dev. Только достоверные пассивные признаки, честный confidence, без широких шаблонов.
5. Оценка в `run_batch` для каждой HTTP-записи и сервиса перед записью; совпадения — в той же транзакции; сигнатуры загружать раз на прогон; счётчик `signature_hits` в `RunStats`.
6. Дифф: совпадения сигнатур — поле сравнения (например, `signatures` у http/service), появление или пропажа совпадения видны как изменение; новое совпадение категорий admin/iot/staging → interest 3. Существующие тесты диффа — зелёные, плюс новый.
7. API: `GET/POST /api/signatures`, `GET/PUT/DELETE /api/signatures/{id}` (PUT повышает версию; встроенные — только отключить, иначе 409), `POST /api/signatures/validate` (компиляция + проверка на образце из тела, без сохранения), `POST /api/signatures/{id}/test?run_id=` (прогон по сохранённым находкам прогона с расшифровкой headers/TLS, без сохранения), `GET /api/runs/{id}/signature-hits` (сигнатура, версия, категория, confidence, сущность; только имена совпавших полей, без значений).

**B. Импорт/экспорт JSON/CSV (минимум AGH; F-16; тест T-14; угроза CSV-формул)**
1. Экспорт: `GET /api/runs/{id}/export?format=json|csv` — JSON версионированный (`{"format":"asi-results","version":1,"exported_at","run":{…},"hosts":[{address,hostname,state,miss_count,flaps,first/last seen,"services":[{port,protocol,service,product,version,confidence,"signatures":[…],"http":[{url,status_code,title,technologies,cms,favicon_hash,is_admin,is_staging,redirects,server,cookie_names,tls:{subject_cn,issuer_cn,not_after,sans}}]}]}]}`), **без секретов** (ни полных заголовков, ни значений cookie, ни сырых выводов). CSV: строка на сервис/HTTP-находку, фиксированные колонки, RFC 4180 (crate `csv`), экранирование формул (значения, начинающиеся с `=`, `+`, `-`, `@`, tab, CR, получают `'`). `Content-Disposition: attachment`. Плюс `GET /api/runs/{id}/diff/export?format=json|csv`.
2. Импорт целей: `POST /api/targets/import` — JSON (`{"targets":[{"value","label?","notes?"}]}` или массив строк) и CSV с необязательным заголовком (`target|value,label,notes`), через `input::normalize`, с дедупом и ошибками по строкам; лимиты размера и числа записей.
3. Импорт результатов: `POST /api/scans/{id}/import?format=json|csv|nmap` — JSON = формат экспорта (туда-обратно), CSV = колонки экспорта, nmap = `-oX` XML (парсер из `parse.rs`). Создаёт прогон скана с `source='import'` (новая колонка `scan_runs.source`), `target_snapshot` = импортированные адреса (дифф сравнивает только импортированное), `config_snapshot` из скана, stats. Запись **тем же кодом, что у живого скана** (вынести шаг 5 `run_batch` в общую функцию) — одинаковая нормализация и оценка сигнатур. Финализация **без сетевой повторной проверки** (импорт никогда не сканирует) → дифф с предыдущим `done`-прогоном. Активный прогон у скана → 409. Валидация: тело до ~20 MiB (`DefaultBodyLimit` на этих маршрутах — по умолчанию axum даёт 2 MB), адреса — только IP, порты 1–65535, строки обрезаются, лимит хостов; 422 с первыми N ошибками.

**Проверка:** unit — сигнатуры на `core/fixtures/httpx.jsonl` и `nmap_sv.xml`, отказы, экранирование CSV, JSON экспорт→импорт. Интеграционно: скан со `start:false` → импорт JSON → экспорт JSON/CSV → импорт изменённого набора (другой title, новая админка, пропавший сервис) → `/runs/{id}/diff` показывает ровно это → hits сигнатур → своя сигнатура → `/test?run_id=` находит → опасная сигнатура отклонена → импорт nmap XML.

### 9.3 Интеграция после обоих потоков

1. Слить `wip/auth-rbac-overlays` (доделанную) и ветку сигнатур в `dev`. Ожидаемые конфликты: блок `router()` в `api.rs`, `mod`-строки в `main.rs`, `Cargo.toml` (разрешить, затем `cargo build` обновит `Cargo.lock`).
2. Добавить маршруты потока 9.2 в `rbac::ROUTES` (иначе они admin-only); `created_by` для сигнатур — из `CurrentUser`; вызвать загрузку встроенных сигнатур в `main.rs`.
3. Прокси `web/src/app/api/[...path]/route.ts`: пробросить `Authorization`, `Cookie`, `X-ASI-CSRF`; вернуть `Set-Cookie`; методы PATCH/PUT/DELETE; добавить новые пути в allow-list. **Перед правкой `web/` прочитать `web/AGENTS.md`** (версия Next.js с несовместимыми изменениями — сверяться с `node_modules/next/dist/docs/`).
4. Добавить `ASI_ADMIN_PASSWORD` в `.env`, обновить `scripts/lab-scan.sh` и `scripts/diff-demo.sh` (логин → токен в заголовке).
5. `cargo test`, clippy, полный сценарий на lab (§6 + авторизация + сигнатуры + импорт/дифф), обновить README (API, env) и PROJECT.md (§15–§16), push в `dev`.

## 10. Дальше (раунд 2) и вопросы к AGH

- **F-20 окна по часам** — обязательный минимум AGH («konkretne przedziały czasowe»): IANA-часовой пояс (`Europe/Warsaw`), дни недели, окна `HH:MM–HH:MM` (в т.ч. через полночь), DST; запуск и продолжение только внутри окна; тест T-19. Затрагивает `scheduler.rs`, `pipeline.rs` (deadline), `api.rs` (валидация), миграцию.
- **F-02 scope-политика**: одобренные CIDR/домены/порты + исключения, запрет loopback/link-local/metadata/multicast, проверка после DNS, preview нагрузки до запуска (T-03…T-05).
- **F-11 глобальный бюджет pps** (token bucket: глобальный → скан → подсеть), kill switch.
- **F-19 пагинация** findings/targets/scans + сводка для дашборда (главные изменения, таймлайн прогонов).
- **DefectDojo**: проверено по живой схеме API v3.5.201 — `POST /api/v2/import-scan/` (первый прогон), `/reimport-scan/` с `close_old_findings` (следующие); типы «Nmap Scan», «Naabu Scan», «httpx Scan», «Generic Findings Import» (наши наблюдения как информационные findings); через outbox со своим статусом; сырьё уже в `run_artifacts` (nmap XML батчей слить в один `<nmaprun>`).
- **Контракт с фронтом** (F-17/F-18): OpenAPI, переход бэкенда на `/api/v1`, режим `proxy` без моков на демо.
- Мелочи: F-22, F-23 (только имена cookie), F-13 (классификация полей), F-25, F-27, R-03, R-04; CI (GitHub Actions: `cargo test` + clippy); **бенчмарк 10k IP** в lab (реальные цифры для слайда); презентация ≤10 слайдов (план — PROJECT.md §19).
- **Спросить у менторов AGH (Discord):** формат JSON/CSV для импорта/экспорта; разрешённые порты, темп и окна в их лаборатории; примеры сигнатур, которые они ждут.

## 11. Грабли и подсказки

- axum 0.8: пути `/{id}`; тело по умолчанию ≤ 2 MB (`DefaultBodyLimit`). sqlx 0.9: запросы проверяются только во время выполнения — каждую новую SQL-ветку прогонять на живой БД.
- Ключ шифрования передаётся в SQL параметром (`pgp_sym_encrypt($x, $key)`): защищает диск и бэкапы, но не скомпрометированный сервер БД; ротации ключа нет.
- nmap XML разбирается `roxmltree` с `allow_dtd`; httpx ставится под именем `pd-httpx` (конфликт с Python-утилитой `httpx`).
- `ALTER TYPE ... ADD VALUE` (0005) работает в транзакции миграции на PG ≥ 12, но новое значение нельзя использовать в той же транзакции.
- Контейнеры `core`/`web` — non-root, `cap_drop: ALL`, `no-new-privileges`; сканы только connect (`-sT`, naabu `-s c`), без `NET_RAW`.
- Ветки агентов Claude Code создаются в `.claude/worktrees/` внутри репозитория (в `.gitignore`); каждая сборка Rust там идёт с нуля.

## 12. Как продолжить с Claude Code на новом ПК

Открыть Claude Code в корне клона и начать с:

> Прочитай `HANDOFF.md` и `PROJECT.md`. Правила из §2 HANDOFF обязательны (работа в `dev`, `main` только по моей команде, `.env` не коммитить). Начни с проверки `a97eaa0` на лабе по §6, потом продолжим §8.1 и §9.2 двумя агентами в отдельных worktree.
