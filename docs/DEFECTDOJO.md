# DefectDojo: локальная инстанция и интеграция

> 2026-11-22. Проверено вживую: ASI → DefectDojo 3.4.304 в Docker на том же ПК, 12/12 проверок
> (скан лабы → автоэкспорт → находки в DefectDojo; ручной экспорт evidence → файл в engagement).

## Запуск

```bash
# секреты DefectDojo в .env (см. .env.example и README): DD_SECRET_KEY, DD_CREDENTIAL_AES_256_KEY,
# DD_DATABASE_PASSWORD, DD_ADMIN_PASSWORD — случайные строки
docker compose up -d                              # DefectDojo входит в общий compose.yaml
```

Одноразовый сервис `dojo-connect` ждёт DefectDojo, получает API-токен администратора и сохраняет его в
настройках ASI (автоэкспорт, оценка ≥ 60), затем нажимает «Testuj połączenie». Если ASI уже подключён, он ничего
не меняет. Переподключить вручную: `python scripts/defectdojo/setup.py .env`; лог: `docker compose logs dojo-connect`.

- DefectDojo: **http://localhost:8081**, логин `admin`, пароль — `DD_ADMIN_PASSWORD` из `.env`.
- Первый запуск: ~1,7 ГБ образов, инициализация базы ~1 минута; при работе ~2–3 ГБ RAM.
- Остановить только DefectDojo: `docker compose stop dojo-nginx dojo-uwsgi dojo-celerybeat dojo-celeryworker`.

Сервисы `dojo-*` в `compose.yaml` — официальный `docker-compose.yml` DefectDojo (релиз 3.4.304) с тремя отличиями:
образы с Docker Hub (реестр `registry.defectdojo.com` по умолчанию логирует каждую загрузку с IP),
секреты из `.env` вместо общих значений по умолчанию, своя внутренняя сеть — наружу только nginx
(для ядра — `http://dojo-nginx:8080`, для браузера — `http://localhost:8081`).

## Как устроена интеграция

| Что | Как |
|---|---|
| Настройка | **Administracja → Integracje**: адрес и API-токен (токен хранится зашифрованным, в ответах только маска). Адрес включает интеграцию, пустой — выключает |
| «Testuj połączenie» | проверяет адрес и токен, затем находит или **создаёт** в DefectDojo тип продукта «ASI», продукт «ASI — CBI AGH» и engagement «ASI — skanowanie ciągłe»; панель показывает их с номерами |
| Экспорт «Finding informacyjny» | выбранные находки → `/api/v2/import-scan/` (парсер Generic Findings Import), каждый экспорт — отдельный тест с датой; `unique_id_from_tool` = id находки ASI (дедупликация в DefectDojo) |
| Экспорт «Evidence» | на каждую находку — JSON-файл с доказательствами (заголовки, баннеры, TLS, технологии, история) в файлы engagement |
| Severity | из оценки ASI: ≥80 High, ≥60 Medium, ≥40 Low, иначе Info; правило записано в описании каждой находки |
| Автоэкспорт | «Wysyłaj automatycznie po każdym skanie»: после каждого завершённого прогона уходят его новые находки с оценкой ≥ порога; уже отправленные пропускаются; ошибки не влияют на скан |
| История | «Historia wysyłek»: кто (или «automatycznie (po skanie)»), сколько, как, результат, ссылка; находка помечается «wysłano do DefectDojo» со ссылкой |
| Ссылки | ведут на `DEFECTDOJO_PUBLIC_URL` (в `compose.yaml` — `http://localhost:8081`), а не на внутренний адрес |

## Проверка (2026-11-22)

| Шаг | Результат |
|---|---|
| `setup.py` | токен получен; «Połączono z http://dojo-nginx:8080 — token ważny. Produkt „ASI — CBI AGH” (#1), engagement „ASI — skanowanie ciągłe” (#1)» |
| Скан лабы `172.30.0.0/28` (профиль Laboratorium) | завершён; автоэкспорт записан в историю ASI как успешный |
| DefectDojo API: тесты engagement #1 | появился новый тест «ASI …» |
| DefectDojo API: находки теста | «Panel Administracyjny: Admin Login - Staging», severity **Medium**, в описании хост `172.30.0.12` и правило оценки |
| Ручной экспорт одной находки как evidence | 1 отправлена; в файлах engagement появился JSON |
| Ссылки в ответе ASI | `http://localhost:8081/...` |

## Ограничения

- Находки ASI — это поверхность атаки (панели, staging, версии), а не уязвимости; severity — приоритет
  внимания по оценке ASI, а не CVSS.
- Сырые выводы сканеров (nmap XML, naabu, httpx) хранятся зашифрованными и подходят для родных парсеров
  DefectDojo («Nmap Scan», «Naabu Scan», «httpx Scan»), но их отправка пока не сделана.
- Проверено с DefectDojo 3.4.304 по HTTP внутри Docker; HTTPS-инстанция — через `verify_tls` в настройках.
