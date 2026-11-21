# hacknation — Attack Surface Intelligence

HackNation, задание №3 (AGH). Циклическое discovery-сканирование больших сетей (>10 000 IP)
с детектом изменений во времени, кастомными сигнатурами, RBAC, шифрованием и интеграцией с DefectDojo.

**Полная спецификация и «зачем всё это» — [PROJECT.md](PROJECT.md).**

## Структура монорепо

| Путь | Что | Ответственный |
|------|-----|---------------|
| `core/` | Rust (axum + tokio + sqlx): API и оркестратор скана | A (ядро), B (данные/diff) |
| `core/migrations/` | Схема PostgreSQL (pgcrypto, RBAC-роли, diffs, audit) | B |
| `web/` | Next.js дашборд (перенесён из SWOT) + `/api` прокси на core | C |
| `tools/` | Пиннутые версии ProjectDiscovery + установщик с проверкой SHA-256 | A |
| `compose.yaml` | db + core + web, профиль `lab` — тестовые сервисы для демо | все |

## Запуск

```bash
cp .env.example .env
sed -i "s|^ASI_DATA_KEY=.*|ASI_DATA_KEY=$(openssl rand -base64 32)|" .env
docker compose up --build -d                 # db + core + web
docker compose --profile lab up -d           # + тестовая лаба 172.30.0.0/24
```

- Дашборд: http://localhost:3000
- API (http://localhost:8000/api):

| Метод | Путь | Что |
|-------|------|-----|
| GET | `/health`, `/tools` | состояние, установленные сканеры |
| GET/POST | `/targets` | список / импорт целей (текст, CSV: первая колонка) |
| GET/POST | `/scans` | список / создание скана (цели + rate, окно, повтор, порты, батч) |
| POST | `/scans/{id}/run` | запустить скан сейчас (новый прогон) |
| GET | `/scans/{id}/runs` | прогоны скана |
| GET | `/runs/{id}` | статус, прогресс, ETA, статистика |
| GET | `/runs/{id}/findings` | хосты (state, miss_count, flaps, first/last seen) → сервисы → HTTP-находки (расшифрованы) |
| GET | `/runs/{id}/diff` | изменения vs предыдущий прогон: new/gone/changed, confidence, interest 1–3 (`?against=<run_id>` — с любым прогоном) |
| POST | `/runs/{id}/cancel` | остановить прогон |

### Демо на лабе

```bash
scripts/diff-demo.sh        # 4 прогона с изменениями лабы + сравнение любых двух (~2.5 мин)
```

Вручную:

```bash
docker compose --profile lab up -d
scripts/lab-scan.sh demo                                  # прогон 1: nginx .10, Apache .11
docker compose --profile lab stop lab-httpd               # "изменение инфраструктуры"
docker compose --profile lab2 up -d lab-admin             # новый хост: админка на staging (.12)
curl -XPOST localhost:8000/api/scans/<scan_id>/run        # прогон 2 того же скана
# окно с паузой/возобновлением:
scripts/lab-scan.sh "window" '"window_minutes":1,"repeat_every_minutes":2,"batch_size":4,"rate_limit_pps":5'
```

Пример создания скана:

```bash
curl -s localhost:8000/api/scans -H 'Content-Type: application/json' -d '{
  "name": "uczelnia", "targets": "10.0.0.0/20\nexample.com",
  "rate_limit_pps": 200, "window_minutes": 120, "repeat_every_minutes": 1440,
  "ports": "100", "batch_size": 256 }'
```

## Разработка без Docker

```bash
docker compose up -d db
cd core && DATABASE_URL=postgres://asi:asi-dev-password@localhost:5432/asi ASI_DATA_KEY=dev cargo run
cd core && cargo test
cd web && npm ci && ASI_API_INTERNAL_URL=http://127.0.0.1:8000 npm run dev
```

(для локального `cargo run` пробросьте порт Postgres: `ports: ["127.0.0.1:5432:5432"]` в `db`).

## Ветки

- `dev` — вся работа.
- `main` — только по команде владельца репозитория.

## Статус

**Пайплайн A (скан) — готов, проверен на лабе:** pre-flight (`nmap -sn`) → порты (`naabu`, connect) →
сервисы (`nmap -sV`) → HTTP/HTTPS (`httpx`: title, код, заголовки, cookie, TLS, редиректы, технологии) →
CMS/админка/staging → Postgres (чувствительные поля и сырые выводы зашифрованы `pgp_sym_encrypt`).
Планировщик: повтор каждые N минут, временные окна с паузой и продолжением с чекпоинта,
адаптивный размер батча по измеренной скорости, ETA, восстановление после рестарта, отмена.

**Diff Engine — готов, проверен на лабе (`scripts/diff-demo.sh`):** сравнение с предыдущим прогоном
в конце каждого прогона, повторная проверка пропавших хостов/портов, статусы unstable → inactive
по порогу `inactive_after_misses`, учёт «миганий», confidence и interest у каждого изменения,
значения в диффах зашифрованы. Правила — PROJECT.md §9.

**Где остановились и как продолжить (в т.ч. на другом ПК)** — [HANDOFF.md](HANDOFF.md).

**Известные проблемы и план** — PROJECT.md §15 (реестр находок) и §17 (дорожная карта).
До закрытия гейтов SEC/SCOPE не запускать вне изолированной лабы и не открывать API в сеть.

Дальше (бэкенд): RBAC + логин, редактирование находок с сохранением между сканами, импорт/экспорт
JSON/CSV, экспорт в DefectDojo (сырые выводы уже в `run_artifacts`), кастомные сигнатуры.
Экраны фронта делает отдельный участник команды.
Фронт пока UI SWOT — экраны переводятся на новый API (`/scanners` ещё не существует, это ожидаемо).

## Лицензия

GPL-3.0 — фронтенд и установщик инструментов взяты из [SWOT](https://github.com/VHJ5TmV0/SWOT) (GPL-3.0),
поэтому проект целиком распространяется под GPL-3.0.
