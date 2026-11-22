# Attack Surface Intelligence — najczęściej zadawane pytania

> Dla klientów i osób, które oceniają wdrożenie: co ASI robi, czy jest bezpieczny dla sieci, ile trwa
> skanowanie i jak chronione są dane. Szczegóły techniczne — w
> [dokumentacji technicznej](DOKUMENTACJA-TECHNICZNA.md). Stan na 22 listopada 2026 r.

## Spis treści

1. [O produkcie](#o-produkcie)
2. [Bezpieczeństwo skanowania](#bezpieczeństwo-skanowania)
3. [Skala i czas skanowania](#skala-i-czas-skanowania)
4. [Wyniki: znaleziska i zmiany](#wyniki-znaleziska-i-zmiany)
5. [Praca analityka](#praca-analityka)
6. [Dostęp, role i ochrona danych](#dostęp-role-i-ochrona-danych)
7. [Wdrożenie i utrzymanie](#wdrożenie-i-utrzymanie)
8. [Ograniczenia](#ograniczenia)

---

## O produkcie

### Czym jest Attack Surface Intelligence (ASI)?

To system, który cyklicznie skanuje duże sieci (dziesiątki tysięcy adresów IP) i pokazuje, **co się w nich
zmieniło od poprzedniego skanu**. Znajduje aktywne hosty, otwarte porty, usługi z wersjami i aplikacje WWW,
rozpoznaje technologie (CMS, frameworki, panele administracyjne, środowiska testowe, urządzenia IoT), a po
każdym przebiegu porównuje wynik z poprzednim: co się pojawiło, co zniknęło, co zmieniło wersję.

### Dla kogo jest ASI?

Dla zespołów bezpieczeństwa i administratorów, którzy odpowiadają za dużą, zmieniającą się infrastrukturę —
uczelni, urzędów, instytucji publicznych. Interfejs jest w języku polskim.

### Czym ASI różni się od jednorazowego skanu?

Jednorazowy skan daje tabelę, która starzeje się w kilka dni. ASI skanuje według harmonogramu, przechowuje
historię i sam wskazuje zmiany: nowy panel administracyjny na serwerze testowym trafia na górę listy
znalezisk zaraz po skanie, w którym się pojawił.

### Czy ASI jest skanerem podatności albo narzędziem do testów penetracyjnych?

Nie. ASI wyłącznie **wykrywa i rozpoznaje**: nie loguje się, nie zgaduje haseł, nie wysyła formularzy ani
ładunków ataku i nie wykorzystuje podatności. Znalezisko w ASI to „warto się temu przyjrzeć”
(np. panel administracyjny albo repozytorium `.git` dostępne z sieci), a nie potwierdzona podatność.

---

## Bezpieczeństwo skanowania

### Kto decyduje, co wolno skanować?

Administrator serwera, a nie użytkownik panelu. W konfiguracji serwera ustawia dozwolone sieci IPv4
(`ASI_ALLOWED_CIDRS`), dozwolone domeny (`ASI_ALLOWED_DOMAINS`, razem z poddomenami), dozwolone porty
(`ASI_ALLOWED_PORTS`) i wykluczenia (`ASI_EXCLUDED_CIDRS`, ważniejsze niż zgody). Skan celu albo portu spoza
listy jest odrzucany jeszcze przed uruchomieniem. Domena jest skanowana tylko wtedy, gdy wskazuje wyłącznie
na zatwierdzone sieci — sprawdzane przed startem i przed każdą częścią skanu. Adresów specjalnych (loopback,
link-local, multicast) nie da się zeskanować nigdy. Domyślnie dozwolona jest tylko izolowana sieć
laboratoryjna i 8 popularnych portów.

### Czy mogę wyłączyć ze skanowania pojedynczy adres w dużej sieci?

Tak. Wystarczy oznaczyć adres (albo mniejszą sieć) jako wykluczony w „Zakresach” — zostanie odjęty od
skanowanej sieci, zanim trafi do narzędzi. Kreator skanu pokazuje, ile adresów wykluczono.

### Czy skan może zaszkodzić usługom w sieci?

ASI jest zaprojektowany tak, by ryzyko było minimalne:

- skanowanie metodą zwykłego połączenia TCP (bez surowych pakietów i bez uprawnień root);
- rozpoznawanie wersji tylko najczęstszymi próbami (`nmap -sV --version-light`), bez skryptów NSE,
  które wyglądają jak próby ataku;
- zapytania HTTP tylko do portów rozpoznanych jako WWW — około 3 zapytań na serwer WWW, plus po jednym
  zapytaniu GET o ścieżki wskazane przez włączone sygnatury (wbudowane: `/.git/HEAD`, `/login`, `/admin/`,
  `/version`); przekierowania nigdy nie są śledzone;
- wspólny limit zapytań na sekundę dla wszystkich jednocześnie trwających skanów;
- okna czasowe: skan działa tylko w wyznaczonych godzinach i dniach tygodnia.

Każde aktywne skanowanie niesie jednak pewne ryzyko dla bardzo wrażliwych urządzeń (stare drukarki, sterowniki
przemysłowe). Takie sieci warto wykluczyć albo skanować profilem „Delikatny” (20 zapytań/s).

### Ile ruchu generuje skan?

Zależy od liczby adresów, portów i limitu tempa ustawionego w profilu. Pomiar w laboratorium: kilka zapytań
HTTP na serwer WWW (3 + próby ścieżek sygnatur), 0 połączeń z internetem. Limit tempa jest przekazywany
narzędziom skanującym; przy bardzo niskich limitach możliwe są krótkie przekroczenia na poziomie pojedynczych
pakietów. Szczegóły: [NOISE.md](NOISE.md).

### Czy cel skanu wie, kto go skanuje?

Tak. Zapytania HTTP mają jawny nagłówek `User-Agent` (domyślnie
`ASI/0.1 (Attack Surface Intelligence; authorised scan)`), więc administratorzy usług widzą w logach, że to
autoryzowany skan, a nie anonimowy ruch.

### Jak awaryjnie zatrzymać wszystkie skany?

Utworzyć na serwerze plik `deploy/control/STOP`. Trwające skany są przerywane, a nowe się nie uruchamiają,
dopóki plik nie zostanie usunięty. W teście laboratoryjnym, od drugiej sekundy po utworzeniu pliku, przez
10 sekund cel nie otrzymał ani jednego pakietu. Pojedynczy skan można też wstrzymać albo anulować w panelu.

### Czy ASI wysyła dane do internetu?

Nie. Rdzeń skanera i baza danych działają w wewnętrznych sieciach Dockera bez wyjścia do internetu; narzędzia
skanujące nie sprawdzają aktualizacji. Na zewnątrz wystawiony jest tylko port panelu (i lokalnego DefectDojo).
Dane trafiają wyłącznie do instancji DefectDojo, którą skonfiguruje administrator.

---

## Skala i czas skanowania

### Ile trwa skan 10 000 adresów?

Pomiar: sieć /18 (**16 382 adresy**, 160 aktywnych hostów, 8 portów) — przy limicie 1000 zapytań/s
**ok. 7 minut** (413 s pracy skanerów), bez limitu ok. 6,5 minuty. Znaleziono 160/160 hostów i 140/140
odcisków serwerów WWW. Czas rośnie z liczbą portów i maleje z limitem tempa. Szczegóły: [BENCHMARK.md](BENCHMARK.md).

### Skąd wiem, ile potrwa skan, zanim go uruchomię?

Kreator „Nowe skanowanie” pokazuje szacunek przed startem: liczbę adresów, podział na podgrupy, przewidywany
czas i to, czy skan zmieści się w oknie czasowym.

### Co się stanie, jeśli skan nie zmieści się w oknie czasowym?

Sieć jest dzielona na podgrupy. Gdy okno się kończy, skan zatrzymuje się po ostatniej ukończonej podgrupie
i wznawia od tego miejsca w następnym oknie (albo — jeśli tak ustawiono — kończy się). Postępu nie trzeba
zaczynać od nowa.

### Czy mogę skanować automatycznie, np. co noc?

Tak. Harmonogramy uruchamiają skan codziennie albo w wybrane dni tygodnia, w zadanym oknie godzin i strefie
czasowej. Skan można też uruchomić od razu („Teraz”) albo powtórzyć zakończony jednym przyciskiem
(„Skanuj ponownie”).

---

## Wyniki: znaleziska i zmiany

### Co ASI znajduje?

- aktywne hosty i otwarte porty;
- usługi z nazwą produktu i wersją;
- dla WWW: tytuł strony, kod odpowiedzi, nagłówki, ciasteczka, certyfikat TLS, przekierowania, favicon,
  rozpoznane technologie, wersja z meta generatora lub stopki strony;
- **znaleziska**: panele administracyjne, środowiska testowe (staging), usługi wrażliwe dostępne z sieci
  (np. bazy danych, RDP, SMB), dopasowania sygnatur — 29 wbudowanych (m.in. phpMyAdmin, Grafana, Jenkins,
  GitLab, kamery IP, interfejsy iDRAC/iLO, drukarki HP, odsłonięte repozytorium `.git`, strony logowania)
  i dowolna liczba własnych.

### Czy po każdym skanie dostanę te same znaleziska od nowa?

Nie. Jeden problem to jedno znalezisko — niezależnie od liczby skanów. Panel pokazuje, kiedy problem
zauważono pierwszy i ostatni raz oraz w ilu skanach. Jeśli kolejny skan go nie widzi, znalezisko jest
oznaczane jako zniknięte i spada z listy najważniejszych.

### Co oznacza priorytet znaleziska?

To ocena od 0 do 100: jak bardzo warto się przyjrzeć. Składa się z kategorii znaleziska (np. panel
administracyjny — 60 punktów), premii za nowość (+20, jeśli pojawiło się od poprzedniego skanu), krytyczności
zakresu ustawionej przez użytkownika (do +20) i kary za niską pewność rozpoznania (−10). Panel pokazuje to
rozbicie przy każdym znalezisku („Dlaczego taki priorytet?”), a analityk może priorytet nadpisać.

### Jak ASI wykrywa zmiany?

Po każdym skanie porównuje wynik z poprzednim przebiegiem tych samych celów i oznacza każdy host, usługę
i stronę jako **Nowy**, **Zmieniony** (np. inna wersja), **Zniknął** albo **Niestabilny**. Porównywane jest
tylko to, co zmierzono w obu skanach: adres, którego nie sprawdzono, nie „znika”.

### Host raz odpowiada, a raz nie. Czy dostanę fałszywy alarm „zniknął”?

Nie od razu. Zanim ASI uzna coś za zniknięte, sprawdza to ponownie po kilku sekundach. Host, który przestał
odpowiadać, najpierw jest **niestabilny**, a nieaktywny dopiero po kilku kolejnych nieudanych skanach
(domyślnie 3, ustawiane od 1 do 100). Powroty są liczone jako „mignięcia”, a mapa dostępności pokazuje,
o których godzinach host odpowiada.

### Czy ASI zauważy, że host działa tylko w dzień?

Tak. Na podstawie historii skanów ASI wykrywa hosty widoczne tylko w określonych godzinach (np. „Widoczny
tylko 08–18”) i pokazuje to w „Zmianach” z uzasadnieniem — pod warunkiem kilku skanów zarówno w tych
godzinach, jak i poza nimi.

### Co zrobić z fałszywym alarmem?

Nadać znalezisku status „Fałszywy alarm”. Statusy (Do analizy, W analizie, Potwierdzone, Fałszywy alarm,
Zaakceptowane ryzyko) zostają po kolejnych skanach.

---

## Praca analityka

### Czy moje zmiany przetrwają kolejny skan?

Tak. Właściciel, krytyczność, tagi, notatki i statusy znalezisk są zapisywane obok danych ze skanu, a nie
zamiast nich, więc kolejny skan ich nie nadpisuje. Każda zmiana ma historię; w razie potrzeby można przywrócić
wartość ze skanu.

### Czy mogę dodać własne reguły rozpoznawania?

Tak — sygnatury. Reguła sprawdza nagłówki, ciasteczka, tytuł strony, kod odpowiedzi, skrót favicon, fragment
HTML strony, wersję usługi albo — bezpiecznym zapytaniem GET — wskazaną ścieżkę (np. czy `/.git/HEAD` jest
dostępne). Przed zapisaniem można ją przetestować na zebranych danych; sygnatury można też importować
i eksportować (JSON). Sygnatury nie logują się, nie wysyłają formularzy i nie śledzą przekierowań.

### Jak dodać sieci do monitorowania?

W sekcji „Zakresy”: ręcznie (adres IP, sieć CIDR do /12, domena) albo z pliku CSV/JSON. Import pokazuje
podgląd z wynikiem walidacji każdego wiersza, zanim cokolwiek zostanie zapisane. Zakresy można opisać
tagami, a potem w kreatorze skanu wybrać je jednym kliknięciem po tagu. Pamiętaj, że skanować można tylko
sieci i domeny zatwierdzone przez administratora serwera.

### Jakie są formaty importu i eksportu?

- cele: import i eksport CSV/JSON;
- wyniki skanu: eksport JSON/CSV; import JSON, CSV i nmap XML (np. wyniki z innego skanera);
- znaleziska: eksport CSV/JSON (z bieżącymi filtrami);
- sygnatury: import i eksport JSON.

Przykładowe pliki są dostępne z poziomu interfejsu.

### Czy ASI współpracuje z DefectDojo?

Tak. DefectDojo jest częścią instalacji i ASI podłącza się do niego sam; można też wskazać własną instancję
(Administracja → Integracje). ASI tworzy w DefectDojo produkt i engagement. Znaleziska trafiają tam
automatycznie po każdym skanie (od wybranego progu priorytetu, każdy problem tylko raz) albo ręcznie z listy
znalezisk — jako znaleziska albo pliki z dowodami. Priorytet ASI jest przeliczany na severity: od 80 — High,
od 60 — Medium, od 40 — Low, poniżej — Info. Szczegóły: [DEFECTDOJO.md](DEFECTDOJO.md).

### Gdzie znajdę instrukcję obsługi panelu?

W panelu: przycisk „Pomoc” w prawym górnym rogu (kolejność pracy, opis sekcji, słowniczek). Na pulpicie nowej
instalacji jest też blok „Jak zacząć”, a <kbd>Ctrl</kbd> + <kbd>K</kbd> otwiera wyszukiwarkę hostów, znalezisk
i sekcji.

---

## Dostęp, role i ochrona danych

### Jakie role są dostępne?

Cztery wbudowane:

| Rola | Uprawnienia |
|---|---|
| Administrator | pełny dostęp, użytkownicy, role, integracje, ustawienia |
| Operator | dodawanie, usuwanie i modyfikacja danych |
| Analityk | modyfikacja i odczyt (bez dodawania i usuwania) |
| Obserwator | tylko odczyt |

Uruchamianie skanów to osobne uprawnienie przyznawane konkretnym osobom. Można też tworzyć **własne role**
z 41 uprawnień. Uprawnienia sprawdza serwer przy każdym zapytaniu — ukrycie przycisku w przeglądarce nie jest
jedynym zabezpieczeniem.

### Jak chronione są dane w bazie?

Wrażliwe pola — banery usług, nagłówki, ciasteczka, dane TLS, treść stron, surowe wyniki skanerów, dowody,
notatki analityków, token DefectDojo — są szyfrowane w PostgreSQL (`pgcrypto`). Klucz szyfrowania jest tylko
w konfiguracji serwera, nigdy w bazie, i można go zmienić bez utraty danych (rotacja z poziomu panelu).
Bez uprawnienia „sensitive:reveal” te pola są w panelu ukryte.

### Jak chronione są konta?

Hasła mają od 12 do 256 znaków i są przechowywane jako skrót Argon2id. Sesja to losowy token w ciasteczku
HttpOnly (SameSite=Strict); baza przechowuje tylko jego skrót SHA-256. Po 5 nieudanych logowaniach na jedno
konto albo 20 z jednego adresu w ciągu 15 minut logowanie jest czasowo blokowane — liczy się prawdziwy adres
użytkownika, więc błędy jednej osoby nie blokują innych. Zmiana roli lub hasła unieważnia sesje.

### Czy widać, kto co zrobił?

Tak. Dziennik zdarzeń zapisuje każdą zmianę i każdą odmowę dostępu: kto, co, kiedy, z jakiego adresu, z jakim
wynikiem. Wpisów nie można edytować ani usuwać; nie trafiają do nich hasła ani tokeny.

### Gdzie są przechowywane dane?

Wyłącznie na serwerze klienta, we własnej bazie PostgreSQL. ASI nie korzysta z usług chmurowych.

---

## Wdrożenie i utrzymanie

### Jakie są wymagania?

Docker (Docker Desktop na Windows/macOS albo Docker Engine z Compose na Linuksie) i około 6 GB RAM razem
z lokalnym DefectDojo. Pierwsze zbudowanie obrazów trwa 5–10 minut.

### Jak wygląda instalacja?

Plik `.env` z kluczem szyfrowania i hasłami (szablon w `.env.example`), a potem jedno polecenie
`docker compose up -d --build` — uruchamia panel, rdzeń, bazę, DefectDojo i sieć laboratoryjną do testów.
Krok po kroku — w [dokumentacji technicznej](DOKUMENTACJA-TECHNICZNA.md#9-uruchomienie).

### Czy panel może działać przez HTTPS?

Tak. Wzorzec wdrożenia produkcyjnego (`compose.production.yaml`) zawiera serwer proxy z TLS, sekrety
w plikach poza repozytorium i obrazy przypięte skrótem SHA-256.

### Jak zrobić kopię zapasową?

Kopia bazy PostgreSQL (`pg_dump`) i — osobno, w bezpiecznym miejscu — klucz szyfrowania `ASI_DATA_KEY`.
Bez klucza zaszyfrowanych pól z kopii nie da się odczytać.

### Czy panel jest dostępny dla osób z niepełnosprawnościami?

Panel jest projektowany zgodnie z WCAG 2.1 AA: domyślnie włączony motyw o wysokim kontraście (do wyboru także
jasny i ciemny), trzy rozmiary tekstu, ograniczanie animacji, obsługa klawiatury i czytników ekranu.
W panelu jest deklaracja dostępności.

### Na jakiej licencji jest ASI?

GPL-3.0. Część instalatora narzędzi pochodzi z projektu SWOT (GPL-3.0), więc cały projekt jest
rozpowszechniany na tej licencji.

---

## Ograniczenia

Uczciwie o tym, czego ASI dziś nie robi:

- skanuje adresy **IPv4** i domeny, które na nie wskazują; IPv6 — nie;
- nie łączy wersji oprogramowania z bazą CVE i nie korzysta ze źródeł pasywnych (np. crt.sh, odwrotny DNS) —
  rdzeń celowo nie ma dostępu do internetu;
- limit tempa jest przekazywany narzędziom skanującym; twardy limit na poziomie pakietów wymaga reguł na
  serwerze lub zaporze;
- wykrywanie hostów widocznych tylko o określonych porach potrzebuje kilku dni historii i nie rozróżnia dni tygodnia;
- skan SYN jest eksperymentalny i domyślnie wyłączony.

Pełna lista: [STATUS.md](STATUS.md).
