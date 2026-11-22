"use client";

import { ArrowRight } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { ADMIN_NAV, NAV, NAV_GROUP_LABEL, type NavItem } from "@/components/layout/nav";
import { Container, PageHeader } from "@/components/layout/page";
import { Kbd, Panel } from "@/components/ui/misc";
import type { Permission } from "@/lib/api/types";
import { useCan } from "@/lib/session";

/** The order of work, as a first-time user should follow it. */
const STEPS: { title: string; text: string; href: string; link: string; perm: Permission }[] = [
  {
    title: "Dodaj zakresy",
    text: "Wpisz adresy IP, sieci CIDR lub domeny, które chcesz monitorować, albo zaimportuj je z pliku CSV/JSON.",
    href: "/targets",
    link: "Zakresy",
    perm: "targets:read",
  },
  {
    title: "Uruchom skanowanie",
    text: "Wybierz cele i profil, a potem uruchom skan od razu albo zaplanuj go w oknie czasowym. Postęp i dziennik widać na żywo.",
    href: "/scans/new",
    link: "Nowe skanowanie",
    perm: "scans:create",
  },
  {
    title: "Przejrzyj wyniki",
    text: "W Zasobach są wszystkie wykryte hosty i usługi, w Znaleziskach — to, co wymaga uwagi. Nadaj znaleziskom status, właściciela i notatki.",
    href: "/findings",
    link: "Znaleziska",
    perm: "findings:read",
  },
  {
    title: "Sprawdź zmiany",
    text: "Po kolejnym skanowaniu panel pokaże, co się pojawiło, zniknęło lub zmieniło od poprzedniego razu.",
    href: "/changes",
    link: "Zmiany",
    perm: "changes:read",
  },
];

const GLOSSARY: { term: string; text: string }[] = [
  { term: "Zakres", text: "Adres IP, sieć CIDR (np. 10.0.0.0/24) albo domena objęta monitoringiem. Wykluczony zakres nigdy nie jest skanowany." },
  { term: "Skanowanie (przebieg)", text: "Jedno przejście skanera po wybranych zakresach: wykrycie hostów, otwartych portów, usług i stron WWW." },
  { term: "Profil", text: "Zestaw portów i tempo skanowania, np. „Laboratorium” albo „Duża sieć”." },
  { term: "Okno skanowania", text: "Godziny, w których wolno skanować. Poza oknem skan czeka i wznawia się w następnym oknie." },
  { term: "Podgrupa", text: "Część sieci skanowana jako całość. Po przerwie skan wznawia się od ostatniej ukończonej podgrupy." },
  { term: "Host i usługa", text: "Host to adres IP, który odpowiedział; usługa — otwarty port z rozpoznanym oprogramowaniem i jego wersją." },
  { term: "Znalezisko", text: "Obserwacja do analizy, np. panel administracyjny, środowisko testowe (staging) albo stara wersja oprogramowania." },
  { term: "Priorytet", text: "Ocena od 0 do 100: jak bardzo warto się przyjrzeć. Najważniejsze znaleziska są na górze listy." },
  {
    term: "Status znaleziska",
    text: "Do analizy, W analizie, Potwierdzone, Fałszywy alarm, Zaakceptowane ryzyko. Statusy, właściciele i notatki zostają po kolejnych skanach.",
  },
  { term: "Nowy, Zmieniony, Zniknął", text: "Wynik porównania z poprzednim skanowaniem: host lub usługa pojawiła się, zmieniła wersję albo przestała odpowiadać." },
  { term: "Niestabilny", text: "Host, który raz odpowiada, a raz nie. Zanim panel uzna go za zniknięty, sprawdza go ponownie." },
  { term: "Sygnatura", text: "Reguła, która rozpoznaje usługę po nagłówkach, tytule strony lub banerze. Tylko rozpoznaje — niczego nie atakuje." },
];

function SectionLink({ item }: { item: Omit<NavItem, "perm"> }) {
  return (
    <li>
      {/* data-button: a whole card is the link, so the contrast theme does not underline its text. */}
      <Link
        href={item.href}
        data-button=""
        className="group flex h-full items-start gap-3 rounded-lg border border-line bg-surface p-3.5 transition-colors hover:border-ink-3 hover:bg-surface-2"
      >
        <item.icon className="mt-0.5 size-5 shrink-0 text-ink-2 group-hover:text-ink" aria-hidden />
        <span className="grid gap-0.5">
          <span className="text-sm font-semibold text-ink">{item.label}</span>
          <span className="text-sm text-pretty text-ink-2">{item.description}</span>
        </span>
      </Link>
    </li>
  );
}

export function HelpView() {
  const can = useCan();
  const groups = [
    ...(["start", "analysis", "scanning"] as const).map((g) => ({ heading: NAV_GROUP_LABEL[g], items: NAV.filter((i) => i.group === g && can(i.perm)) })),
    { heading: "Administracja", items: ADMIN_NAV.filter((i) => can(i.perm)) },
  ].filter((g) => g.items.length);

  return (
    <Container className="pb-12">
      <PageHeader
        title="Pomoc"
        description="Od czego zacząć, co jest w każdej sekcji panelu i co znaczą pojęcia, które w nim widzisz."
      />
      <div className="grid gap-6">
        <Panel id="jak-zaczac" title="Jak pracować z panelem" description="Cztery kroki — w tej kolejności przy pierwszym uruchomieniu.">
          <ol className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {STEPS.map((s, n) => (
              <li key={s.title} className="flex gap-3 rounded-lg border border-line bg-surface-2 p-4">
                <span
                  className="grid size-7 shrink-0 place-items-center rounded-full bg-accent text-sm font-semibold text-accent-ink tabular"
                  aria-hidden
                >
                  {n + 1}
                </span>
                <div className="grid content-start gap-1.5">
                  <h3 className="text-sm font-semibold text-ink">
                    <span className="sr-only">Krok {n + 1}: </span>
                    {s.title}
                  </h3>
                  <p className="text-sm text-pretty text-ink-2">{s.text}</p>
                  {can(s.perm) ? (
                    <Link href={s.href} className="inline-flex w-fit items-center gap-1 text-sm font-semibold text-link hover:underline">
                      {s.link} <ArrowRight className="size-3.5" aria-hidden />
                    </Link>
                  ) : (
                    <span className="text-sm text-ink-2">Twoja rola nie ma dostępu do tej sekcji.</span>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </Panel>

        <Panel id="sekcje" title="Sekcje panelu" description="Te same pozycje są w menu u góry; najedź na nie, aby zobaczyć podpowiedź.">
          <div className="grid gap-5">
            {groups.map((g) => (
              <section key={g.heading} aria-label={g.heading} className="grid gap-2">
                <h3 className="text-xs font-semibold tracking-wide text-ink-2 uppercase">{g.heading}</h3>
                <ul className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {g.items.map((i) => (
                    <SectionLink key={i.href} item={i} />
                  ))}
                </ul>
              </section>
            ))}
          </div>
        </Panel>

        <div className="grid gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
          <Panel id="slowniczek" title="Słowniczek">
            <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-[minmax(9rem,auto)_minmax(0,1fr)]">
              {GLOSSARY.map((g) => (
                <React.Fragment key={g.term}>
                  <dt className="text-sm font-semibold text-ink">{g.term}</dt>
                  <dd className="text-sm text-pretty text-ink-2">{g.text}</dd>
                </React.Fragment>
              ))}
            </dl>
          </Panel>

          <Panel id="skroty" title="Skróty i wygląd">
            <ul className="grid gap-3 text-sm text-ink-2">
              <li>
                <Kbd>Ctrl</Kbd> + <Kbd>K</Kbd> — szukaj adresu IP, hosta, znaleziska albo przejdź do dowolnej sekcji.
              </li>
              <li>
                <span className="font-semibold text-ink">A+</span> w prawym górnym rogu — rozmiar tekstu, motyw (Wysoki kontrast, Jasny, Ciemny) i
                ograniczenie animacji. Wybór zapamiętuje ta przeglądarka.
              </li>
              <li>
                Na każdej liście kliknij wiersz, aby zobaczyć szczegóły; strzałka „‹” nad tytułem wraca do listy.
              </li>
              <li>
                <Link href="/dostepnosc" className="font-semibold text-link hover:underline">
                  Deklaracja dostępności
                </Link>
              </li>
            </ul>
          </Panel>
        </div>
      </div>
    </Container>
  );
}
