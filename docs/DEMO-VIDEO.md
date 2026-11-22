# Демо-видео: сценарий (≈4 минуты)

Всё показываем в панели, без терминала (кроме сцены 9). Что работает — `docs/STATUS.md`.

**Формат записи:** экран 1920×1080, браузер на 110%. Голос за кадром — по репликам ниже. Ожидание сканов
(~15 с на лабе /28) ускорить ×4.

## Подготовка (не в кадре)

```bash
docker compose down -v                    # чистая база (DefectDojo тоже начнёт с нуля)
docker compose up -d --build              # сайт, DefectDojo, лаба; ASI сам подключится к DefectDojo
docker compose --profile lab2 stop lab-admin; docker compose start lab-httpd
```

- В **Administracja → Użytkownicy** создать пользователя `obserwator` с ролью «Odczyt».
- Файл `lab.csv` для импорта:
  ```
  value,name,owner,criticality,tags
  172.30.0.0/28,Laboratorium CBI,CSIRT,high,lab|dmz
  blog.asi.test,Blog wydziału,CSIRT,medium,lab|www
  10.0.0.0/7,Za duży zakres,,,
  ```
- Закрыть лишние вкладки, `.env` не показывать в кадре.

## Сцены

| # | Время | Экран | Действие | Реплика |
|---|---|---|---|---|
| 1 | 0:00–0:15 | Pulpit пустой | — | «Uczelnia ma ponad 10 000 adresów IP. Jednorazowy skan szybko się starzeje — ASI skanuje cyklicznie i pokazuje, co się zmieniło.» |
| 2 | 0:15–0:30 | логин | вход `admin` | «Logowanie: hasła Argon2id, sesja w ciasteczku HttpOnly, role i własne role.» |
| 3 | 0:30–0:55 | Cele | Importuj → `lab.csv` → предпросмотр с ошибкой `/7` → Importuj; фильтр «Każdy tag» → `#lab` | «Import CSV z walidacją każdego wiersza; cele można grupować tagami.» |
| 4 | 0:55–1:25 | Nowe skanowanie | в шаге «Cele» нажать тег `#lab` → «Zaznacz widoczne»; профиль Laboratorium; Teraz → Uruchom | «Wybieramy cele po tagach — przy setkach domen to kilka kliknięć. Skan ma limit tempa i okno czasowe.» Показать живой прогресс и журнал. |
| 5 | 1:25–1:50 | Znaleziska | находки blog.asi.test: `.git`, wersja w stopce, /version | «Sygnatury: nagłówki, HTML, wersja w stopce i bezpieczne zapytania o ścieżki.» |
| 6 | 1:50–2:20 | терминал → Nowe skanowanie | `docker compose stop lab-httpd`, `docker compose --profile lab2 up -d lab-admin`; второй скан | «Zmiana w infrastrukturze: Apache zniknął, pojawił się panel logowania na stagingu.» |
| 7 | 2:20–2:50 | Zmiany | новый хост `.12` первым по «interesowności», пропавший Apache — niestabilny | «Porównanie z poprzednim przebiegiem: co nowe, co zniknęło, co się zmieniło.» |
| 8 | 2:50–3:15 | DefectDojo :8081 | Findings продукта «ASI — CBI AGH» | «Znaleziska trafiają automatycznie do DefectDojo — bez duplikatów.» |
| 9 | 3:15–3:35 | второй браузер (инкогнито) | вход `obserwator` | «Rola tylko do odczytu: brak przycisków edycji, a API odrzuca zapis (403).» |
| 10 | 3:35–4:00 | Skan → Eksport wyników | JSON/CSV | «Eksport wyników; wrażliwe pola są w bazie zaszyfrowane.» |

## Запасной вариант

Если скан в кадре затянулся — склеить с заранее записанным прогоном.
