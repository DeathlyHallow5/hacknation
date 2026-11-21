# Демо-видео: сценарий (≈4 минуты)

Показываем только то, что реально работает (см. `docs/STATUS.md`). Сканы запускаются скриптом — в UI
запуска нет; так и говорим: «сканы планирует ядро, запускаем из терминала».

**Формат записи:** экран 1920×1080, слева браузер (масштаб 110%), справа узкий терминал. Голос за кадром —
по репликам ниже. Монтаж: ожидание сканов (~20 с каждый) ускорить ×4.

## Подготовка (не в кадре)

```bash
docker compose down -v                               # чистая база
docker compose --profile lab up --build -d
docker compose --profile lab2 stop lab-admin 2>/dev/null; docker compose --profile lab start lab-httpd
# пользователь-наблюдатель для показа ролей:
. scripts/_auth.sh   # с API=http://127.0.0.1:8000/api
curl -s "$API/users" -H 'Content-Type: application/json' \
  -d '{"username":"obserwator","password":"<придумать, 12+ символов>","role":"viewer"}'
```

- Файл `lab.csv` для импорта:
  ```
  value,name,owner,criticality,tags
  172.30.0.0/24,Laboratorium CBI,CSIRT,high,lab;dmz
  10.0.0.0/7,Za duży zakres,,,
  ```
- Закрыть лишние вкладки, `.env` не показывать в кадре.

## Сцены

| # | Время | Экран | Действие | Реплика |
|---|---|---|---|---|
| 1 | 0:00–0:15 | титул / Pulpit пустой | — | «Uczelnia ma ponad 10 000 adresów IP. Jednorazowy skan szybko się starzeje — ASI skanuje cyklicznie i pokazuje, co się zmieniło.» |
| 2 | 0:15–0:35 | логин | вход `admin` | «Logowanie: hasła Argon2id, sesja w ciasteczku HttpOnly, cztery role.» |
| 3 | 0:35–1:00 | Zakresy | Importuj → `lab.csv` → предпросмотр показывает ошибку `/7` → Importuj | «Import CSV z walidacją każdego wiersza — zbyt duży zakres odrzucony, zanim cokolwiek zeskanujemy.» |
| 4 | 1:00–1:30 | терминал + Pulpit | `scripts/diff-demo.sh` (прогон 1) | «Skan: wykrywanie hostów, portów, wersji usług, nagłówków i TLS, z limitem tempa.» Pulpit: 2 aktywne hosty, nginx i Apache w technologiach. |
| 5 | 1:30–2:10 | Pulpit | скрипт гасит Apache и поднимает админку → прогон 2 | «Zmiana w infrastrukturze: Apache zniknął, pojawił się panel logowania na stagingu.» Показать: карточка zmian (nowe/zniknęły), карта адресов (новый адрес зелёный), в топ-находках первым — «Panel administracyjny: Admin login - staging». |
| 6 | 2:10–2:40 | карточка находки | Szczegóły → доказательства, «Dlaczego taki priorytet?» → статус «Potwierdzone», заметка → Zapisz | «Każde znalezisko ma dowody i uzasadnienie priorytetu. Analityk zmienia status — notatka jest szyfrowana i przetrwa kolejne skany.» |
| 7 | 2:40–3:05 | Pulpit | прогоны 3–4: Apache «inactive», потом вернулся | «Host, który nie odpowiada, najpierw jest niestabilny, a dopiero po kilku pominięciach nieaktywny. Gdy wraca — liczymy to jako „mignięcie”, a nie nowy host.» Показать шкалу изменений и статус той же находки — по-прежнему «Potwierdzone». |
| 8 | 3:05–3:30 | второй браузер (инкогнито) | вход `obserwator` | «Rola tylko do odczytu: brak przycisków edycji, a API odrzuca zapis (403) — uprawnienia sprawdza serwer, nie przeglądarka.» Показать, что поле заметок недоступно; у админа — блок «Aktywność» с записями отказов. |
| 9 | 3:30–3:45 | терминал | `docker compose exec db psql -U asi asi -c "select headers_enc from http_findings limit 1"` | «Wrażliwe pola są w bazie zaszyfrowane.» |
| 10 | 3:45–4:00 | Pulpit | Eksport → CSV | «Eksport do CSV i JSON. Dalej: sygnatury, harmonogram w godzinach i DefectDojo.» |

## Чего в кадре не делать

- Не открывать пункты меню Znaleziska / Zmiany / Zasoby / Skanowania / Sygnatury / Administracja — страниц
  ещё нет (404).
- Не нажимать «Wyślij do DefectDojo» и «Nowe skanowanie» — интеграции и запуска из UI нет.
- Не называть цифры производительности на 10 000 IP, пока не сделан бенчмарк.

## Запасной вариант

Если скан в кадре затянулся — склеить с заранее записанным прогоном; если UI недоступен — показать то же
через `scripts/diff-demo.sh`: он печатает дифф с приоритетами в терминале.
