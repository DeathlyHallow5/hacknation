# Attack Surface Intelligence

**Видеть свою сеть так, как её видит атакующий — и замечать, что в ней изменилось.**

*System cyklicznego skanowania dużych sieci z wykrywaniem zmian w czasie — HackNation 2026, zadanie №3, CBI AGH.*

ASI по расписанию обходит большие сети (десятки тысяч адресов), безопасно и с ограничением темпа находит
живые хосты, открытые порты, сервисы и веб-приложения, распознаёт технологии — и после каждого прогона
показывает **разницу с прошлым разом**: что появилось, что пропало, что поменяло версию и какие хосты
«мигают». Аналитик работает в веб-панели на польском языке: правит данные, ставит статусы находкам,
запускает сканы, пишет свои сигнатуры, выгружает результаты в DefectDojo.

---

## Что умеет

| | |
|---|---|
| **Цели** | IP, CIDR, домены; вручную или импорт CSV/JSON; владелец, критичность, теги, исключения |
| **Безопасный скан** | сканер трогает только сети и порты, одобренные администратором; общий лимит запросов/с; аварийная остановка одним файлом; деление сети на подгруппы с адаптивным размером, оценка времени до запуска, окна по часам и дням недели (вне окна — пауза и продолжение с того же места), честный User-Agent, никаких эксплойтов; у ядра нет выхода в интернет |
| **Что находит** | живые хосты, порты, сервисы и версии (`nmap -sV`), для веба — заголовок, код ответа, заголовки, cookie, TLS, редиректы, favicon, технологии; CMS, фреймворки, панели администрирования, staging, IoT |
| **Изменения во времени** | новые / пропавшие / изменённые хосты и сервисы, повторная проверка перед «пропал», нестабильные хосты, оценка «интересности» каждого изменения, карта доступности по часам |
| **Свои сигнатуры** | правила по заголовкам, cookie, title, favicon, баннерам, фрагменту HTML и версии в стопке страницы, безопасные GET-пробы путей (`/login`, `/admin/`, `/version`, `/.git/HEAD` — без попыток входа); извлечение версии; проверка на тестовых данных, импорт/экспорт; 29 встроенных |
| **Правки аналитика** | владелец, критичность, теги, заметки, статусы находок — **сохраняются при следующих сканах**, с историей правок |
| **Роли (RBAC)** | 4 встроенные роли из задания + **свои роли** из 41 права; проверка на сервере по каждому запросу, журнал аудита |
| **Защита данных** | баннеры, заголовки, cookie, заметки и сырые выводы сканеров зашифрованы в PostgreSQL (`pgcrypto`), сессии — HttpOnly-cookie + CSRF, пароли — Argon2 |
| **Импорт / экспорт** | цели и результаты в JSON/CSV, импорт результатов nmap XML, экспорт в **DefectDojo** |

## Как это работает

```mermaid
flowchart LR
    UI["Панель (Next.js)<br/>localhost:3000"] -- "/api/v1 (proxy)" --> CORE["Ядро (Rust, axum)"]
    CORE --> DB[("PostgreSQL<br/>pgcrypto")]
    CORE --> SCHED["Планировщик<br/>окна, паузы, чекпоинты"]
    SCHED --> P1["1. pre-flight<br/>nmap -sn"] --> P2["2. порты<br/>naabu"] --> P3["3. сервисы<br/>nmap -sV"] --> P4["4. веб<br/>httpx"] --> P5["5. сигнатуры<br/>и diff"]
    P5 --> DB
    CORE -. "экспорт" .-> DD["DefectDojo"]
```

Каждый прогон делит сеть на подгруппы и подбирает их размер по измеренной скорости; прогресс идёт в панель
в реальном времени (SSE). После прогона ядро сравнивает результат с предыдущим, перепроверяет пропавшее и
пересчитывает сигнатуры.

## Быстрый старт

Нужен только **Docker** (Docker Desktop на Windows/macOS или Docker Engine + Compose на Linux), ~4 ГБ RAM.

**1. Настройки** — создайте `.env` со случайными ключами и паролями (ASI и DefectDojo).

Windows (PowerShell):

```powershell
Copy-Item .env.example .env
function New-Secret($n) { $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b) }
function New-Hex($n) { $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); -join ($b | ForEach-Object { '{0:x2}' -f $_ }) }
(Get-Content .env) -replace '^ASI_DATA_KEY=.*', "ASI_DATA_KEY=$(New-Secret 32)" -replace '^ASI_ADMIN_PASSWORD=.*', "ASI_ADMIN_PASSWORD=$(New-Secret 18)" `
  -replace '^DD_SECRET_KEY=.*', "DD_SECRET_KEY=$(New-Hex 32)" -replace '^DD_CREDENTIAL_AES_256_KEY=.*', "DD_CREDENTIAL_AES_256_KEY=$(New-Hex 16)" `
  -replace '^DD_DATABASE_PASSWORD=.*', "DD_DATABASE_PASSWORD=$(New-Hex 16)" -replace '^DD_ADMIN_PASSWORD=.*', "DD_ADMIN_PASSWORD=$(New-Hex 12)" | Set-Content .env -Encoding ascii
```

Linux / macOS:

```bash
cp .env.example .env
sed -i "s|^ASI_DATA_KEY=.*|ASI_DATA_KEY=$(openssl rand -base64 32)|" .env
sed -i "s|^ASI_ADMIN_PASSWORD=.*|ASI_ADMIN_PASSWORD=$(openssl rand -base64 18)|" .env
sed -i "s|^DD_SECRET_KEY=.*|DD_SECRET_KEY=$(openssl rand -hex 32)|; s|^DD_CREDENTIAL_AES_256_KEY=.*|DD_CREDENTIAL_AES_256_KEY=$(openssl rand -hex 16)|" .env
sed -i "s|^DD_DATABASE_PASSWORD=.*|DD_DATABASE_PASSWORD=$(openssl rand -hex 16)|; s|^DD_ADMIN_PASSWORD=.*|DD_ADMIN_PASSWORD=$(openssl rand -hex 12)|" .env
```

По умолчанию сканировать можно только лабу `172.30.0.0/24` и 8 портов (22, 80, 443, 3306, 5432, 6379, 8080, 8443).
Свои сети и порты — переменные `ASI_ALLOWED_CIDRS` и `ASI_ALLOWED_PORTS` в `.env` (см. `.env.example`).

**2. Запуск** — один `compose.yaml` поднимает всё: базу, ядро, панель, DefectDojo и тестовую лабу.

```bash
docker compose up -d --build
```

Первая сборка занимает 5–10 минут, первый старт DefectDojo (миграции) — ещё 2–3 минуты; затем ASI сам
подключается к нему (сервис `dojo-connect`). Если Docker Hub отвечает `429 Too Many Requests`, соберите через
зеркало: `ASI_BASE_REGISTRY=mirror.gcr.io/library docker compose up -d --build`.

**3. Вход**

| Что | Адрес | Логин | Пароль |
|---|---|---|---|
| Панель ASI | http://localhost:3000 | `admin` | `ASI_ADMIN_PASSWORD` из `.env` |
| DefectDojo | http://localhost:8081 | `admin` | `DD_ADMIN_PASSWORD` из `.env` |

Дополнительно: `docker compose --profile testlab up -d` — большая лаба TestLab (см. ниже).
Остановить всё: `docker compose --profile testlab --profile lab2 down` (данные остаются в томах).

## Проверка на лабе через веб-интерфейс

Лаба — изолированная Docker-сеть `172.30.0.0/24` без выхода наружу: nginx на `.10` (`www.asi.test`), Apache на `.11`
(`intranet.asi.test`), сайт «CMS» на `.13` (`blog.asi.test`: meta generator, версия в стопке, `X-Powered-By`,
открытый `/.git/HEAD`, `/version`, `/login`, `/admin/` — на нём видны все типы сигнатур). Цели можно задавать и
доменами из зоны `asi.test` (`ASI_ALLOWED_DOMAINS`).
Сканировать чужие сети без разрешения нельзя — для проверки достаточно лабы.

1. **Zakresy → Dodaj zakres** — добавьте `172.30.0.0/28` (имя, например, «Lab /28»).
2. **Skanowania → Nowe skanowanie** — отметьте цель, профиль **Laboratorium** (порты, одобренные
   администратором), термин **Teraz**, затем **Uruchom skanowanie**. Откроется страница скана с прогрессом и
   журналом в реальном времени; прогон /28 идёт около 15 секунд. Профили с top-100/top-1000 портов
   сканируют только те из них, что одобрены в `ASI_ALLOWED_PORTS` (оценка перед запуском их перечислит);
   для сетей от 10 000 адресов — профиль **Duża sieć** (1000 запросов/с, /18 — около 7 минут).
3. **Pulpit, Zasoby, Znaleziska** — найденные хосты, сервисы с версиями, веб-отпечатки.
4. **Измените инфраструктуру** — выключите Apache и поднимите новый хост с «админкой на staging»:

   ```bash
   docker compose stop lab-httpd
   docker compose --profile lab2 up -d lab-admin
   ```

5. Запустите новый скан с той же целью и профилем (как в шаге 2) — ядро сравнит его с прошлым прогоном
   по тем же целям. **Zmiany** покажет новый хост `.12` с панелью администратора (высокая «интересность»)
   и пропавший Apache — сначала как нестабильный, после следующих прогонов как неактивный.
6. Дополнительно: поправьте владельца или теги хоста и пересканируйте — правка останется; создайте
   свою роль в **Administracja → Role** и войдите пользователем с ней; выгрузите результаты в JSON/CSV.

Вернуть лабу в исходное состояние: `docker compose start lab-httpd` и
`docker compose --profile lab2 stop lab-admin`.

### TestLab — большая лаба

`docker compose --profile testlab up -d` добавляет в ту же изолированную сеть стенды команды (несколько ГБ образов,
без портов на хосте — их видит только сканер). Цель для скана — `172.30.0.16/28` и `172.30.0.32/28` или
вся `172.30.0.0/24`; порты вроде 21, 3000, 5672, 15672 сканируются после добавления в `ASI_ALLOWED_PORTS`.

| Адрес | Домен | Сервис |
|---|---|---|
| `.20` / `.21` | `wp.asi.test` / `db.asi.test` | WordPress 6 + MariaDB 11 |
| `.22` | `pma.asi.test` | phpMyAdmin |
| `.23` | `redis.asi.test` | Redis 7 (без пароля) |
| `.24` | `proxy.asi.test` | Nginx Proxy Manager (80/81/443) |
| `.25` / `.26` | `traefik.asi.test` | Traefik (дашборд :8080) → Toxiproxy (задержка `TL_LATENCY_MS`) → WordPress |
| `.30` / `.31` | `old.asi.test` | устаревший WordPress 4.7 + MySQL 5.7 |
| `.32` | `adminer.asi.test` | Adminer |
| `.33` | `ftp.asi.test` | vsftpd (FTP, 21) |
| `.34` | `dvwa.asi.test` | DVWA (уязвимое веб-приложение) |
| `.40` | `api.asi.test` | httpbin |
| `.41` | — | PostgreSQL 16 |
| `.42` | `mq.asi.test` | RabbitMQ + панель (5672/15672) |
| `.43` | `git.asi.test` | Gitea (3000) |
| `.44` | `app.asi.test` | nginx |

## Границы сканирования и остановка

- **Что можно сканировать** решает администратор сервера, а не пользователь панели: `ASI_ALLOWED_CIDRS`
  (IPv4-сети), `ASI_ALLOWED_DOMAINS` (домены и их поддомены — каждый должен резолвиться только в разрешённые сети,
  это проверяется при оценке и перед каждой подгруппой), `ASI_ALLOWED_PORTS` (порты), `ASI_EXCLUDED_CIDRS`
  (исключения сильнее разрешений).
  Цель вне разрешённого или порт вне списка — отказ ещё до запуска; служебные сети (loopback, link-local,
  multicast) запрещены всегда.
- **Общий лимит** `ASI_GLOBAL_PPS` делится между всеми одновременными прогонами (`ASI_MAX_RUNS`).
- **Аварийная остановка**: создайте файл `deploy/control/STOP` — запущенные сканеры прерываются, новые
  не стартуют, пока файл не удалят.
- Ядро и база живут во внутренних сетях Docker без выхода наружу; наружу опубликован только порт панели.
  Скриптам из `scripts/`, которым нужен API ядра на `127.0.0.1:8000`, — оверрайд
  `docker compose -f compose.yaml -f compose.api.yaml up -d` (только для разработки).
- Шаблон для боевого развёртывания (HTTPS-прокси, секреты из файлов, образы по digest) —
  `compose.production.yaml` и [deploy/SECURITY.md](deploy/SECURITY.md); проверка в изолированной лаборатории —
  [docs/SECURITY-LAB-2026-11-22.md](docs/SECURITY-LAB-2026-11-22.md).

## DefectDojo

Локальный DefectDojo входит в общий `compose.yaml` и подключается к ASI сам при первом старте (сервис
`dojo-connect`; если настройки уже есть — ничего не меняет). Переподключить вручную:
`python scripts/defectdojo/setup.py .env`.

DefectDojo открывается на http://localhost:8081 (`admin` / `DD_ADMIN_PASSWORD` из `.env`). Продукт и engagement
ASI создаёт сам; находки уходят автоматически после каждого скана (оценка ≥ 60) или вручную из «Znaleziska» —
как находки или как файлы-доказательства. Подробности и проверка — [docs/DEFECTDOJO.md](docs/DEFECTDOJO.md).

## Цифры

| Замер | Результат |
|---|---|
| Сеть /18 (16 382 адреса, 160 живых хостов), 8 портов, 1000 запросов/с | **7 мин 56 с**, найдено 160/160 хостов, 160/160 сервисов с версией, 140/140 веб-отпечатков |
| Лаба /24, top-100 портов при 100 запросах/с | 280 с |
| Лаба /28, профиль Laboratorium (8 портов) | 12–18 с |
| Шум у цели после чистки | 3 HTTP-запроса на веб-сервер, 0 «эксплойтных» путей, 0 соединений с интернетом |

Подробности и журнал всех замеров — [docs/BENCHMARK.md](docs/BENCHMARK.md), [docs/benchmarks/](docs/benchmarks/),
[docs/NOISE.md](docs/NOISE.md).

## Стек

| Часть | Технологии |
|---|---|
| Ядро | Rust: axum, tokio, sqlx; Argon2, SHA-256 сессии |
| Сканеры | nmap, naabu, httpx (ProjectDiscovery; версии закреплены, SHA-256 проверяется при сборке) |
| Данные | PostgreSQL 17 + pgcrypto |
| Панель | Next.js 16, React 19, TypeScript, Tailwind CSS 4, TanStack Query |
| Запуск | Docker Compose; контейнер ядра без root и без capabilities |

## Документация

| Документ | О чём |
|---|---|
| [PROJECT.md](PROJECT.md) | полная спецификация, модель угроз, правила diff |
| [docs/API-CONTRACT.md](docs/API-CONTRACT.md) | контракт панели и ядра (`/api/v1`): эндпоинты, права, SSE, форматы, дизайн-система |
| [docs/STATUS.md](docs/STATUS.md) | что работает и что нет |
| [docs/BENCHMARK.md](docs/BENCHMARK.md) | производительность и рассмотренные альтернативы (RustScan, SYN, `-p-`) |
| [docs/NOISE.md](docs/NOISE.md) | сколько трафика сканер создаёт у цели и как его сократили |
| [docs/DEFECTDOJO.md](docs/DEFECTDOJO.md) | локальный DefectDojo, как устроен экспорт и что проверено |
| [docs/DEMO-VIDEO.md](docs/DEMO-VIDEO.md) | сценарий демо-видео |

## Разработка

```bash
docker compose up -d db                       # только база
cd core && cargo test                         # тесты ядра
cd frontend && npm ci && npm run dev          # панель на встроенных демо-данных (ASI_API_MODE=mock)
```

Проверки «от начала до конца» ходят через панель, как браузер: `python -I -X utf8 scripts/e2e/api_check.py .env`
(а также `roles_check`, `scope_check`, `start_now_check`, `signatures_domains_check`, `defectdojo_check`,
`lab_demo_check`). Для бенчмарка (`scripts/bench/`) добавьте его сеть в `ASI_ALLOWED_CIDRS`.

Панель умеет работать без ядра (`ASI_API_MODE=mock`), с ядром (`proxy`, так в Docker) или смешанно (`hybrid`) —
см. [docs/API-CONTRACT.md](docs/API-CONTRACT.md).

Работа ведётся в ветке `dev`; `main` — стабильная версия.

## Лицензия

GPL-3.0 — установщик инструментов взят из [SWOT](https://github.com/VHJ5TmV0/SWOT) (GPL-3.0),
поэтому проект целиком распространяется под GPL-3.0.
