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
- API: http://localhost:8000/api/health · `/api/tools` · `/api/targets` · `/api/scans`

Пример импорта целей:

```bash
curl -s localhost:8000/api/targets -H 'Content-Type: application/json' \
  -d '{"text":"172.30.0.0/24\nexample.com\n10.0.0.5"}'
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

## Статус скелета

Готово: схема БД, нормализация IP/CIDR/доменов (+тесты), матрица RBAC (+тесты), базовый diff (+тесты),
запуск внешних движков с таймаутом, API health/tools/targets/scans, Compose.
Фронт пока UI SWOT — экраны переводятся на новый API (`/scanners` ещё не существует, это ожидаемо).

## Лицензия

GPL-3.0 — фронтенд и установщик инструментов взяты из [SWOT](https://github.com/VHJ5TmV0/SWOT) (GPL-3.0),
поэтому проект целиком распространяется под GPL-3.0.
