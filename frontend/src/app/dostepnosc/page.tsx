import type { Metadata } from "next";
import Link from "next/link";
import { LogoMark } from "@/components/brand/logo";

export const metadata: Metadata = { title: "Deklaracja dostępności" };

export default function AccessibilityPage() {
  return (
    <div className="min-h-dvh bg-canvas">
      <header className="bg-chrome text-chrome-ink">
        <div className="mx-auto flex h-14 max-w-3xl items-center gap-2.5 px-6">
          <LogoMark className="shrink-0 text-chrome-ink" />
          <Link href="/" className="shrink-0 font-extrabold">
            CBI AGH
          </Link>
          <span className="min-w-0 truncate text-sm text-chrome-ink-2">Attack Surface Intelligence</span>
        </div>
      </header>
      {/* Running text is held to about 65 characters per line. */}
      <main id="main" className="mx-auto grid max-w-3xl gap-6 px-6 py-10 text-base leading-relaxed">
        <h1 className="text-[1.75rem] leading-tight font-semibold">Deklaracja dostępności</h1>
        <p className="max-w-[65ch] text-pretty">
          Centrum Bezpieczeństwa Informacji AGH zobowiązuje się zapewnić dostępność aplikacji Attack Surface Intelligence zgodnie z ustawą z dnia 4 kwietnia 2019 r. o
          dostępności cyfrowej stron internetowych i aplikacji mobilnych podmiotów publicznych.
        </p>
        <section className="grid max-w-[65ch] gap-2">
          <h2 className="text-xl font-semibold">Stan dostępności</h2>
          <p className="text-pretty">Aplikacja jest projektowana zgodnie z wytycznymi WCAG 2.1 na poziomie AA. To wersja prototypowa; część wymagań jest w trakcie weryfikacji.</p>
        </section>
        <section className="grid max-w-[65ch] gap-2">
          <h2 className="text-xl font-semibold">Ułatwienia</h2>
          <ul className="grid list-disc gap-1 pl-5">
            <li>Trzy rozmiary tekstu (A, A+, A++) oraz wersja o wysokim kontraście w menu „A+” w nagłówku.</li>
            <li>Krój pisma Atkinson Hyperlegible, zaprojektowany z myślą o czytelności i rozróżnianiu podobnych znaków (0 i O, 1 i l).</li>
            <li>Statusy zawsze oznaczone tekstem i ikoną, nie tylko kolorem; wykresy mają legendy i widok tabeli.</li>
            <li>Pełna obsługa klawiaturą, widoczny fokus, link „Przejdź do treści”, wyszukiwanie skrótem Ctrl+K.</li>
            <li>Możliwość ograniczenia animacji (także zgodnie z ustawieniem systemowym).</li>
          </ul>
        </section>
        <section className="grid max-w-[65ch] gap-2">
          <h2 className="text-xl font-semibold">Informacje zwrotne i kontakt</h2>
          <p className="text-pretty">
            Problemy z dostępnością można zgłaszać na adres <span className="mono [overflow-wrap:anywhere]">dostepnosc@cbi.uczelnia.example</span>. Odpowiemy nie później niż w ciągu 7 dni.
          </p>
        </section>
        <p className="text-sm text-ink-2">Data sporządzenia deklaracji: 21.11.2026.</p>
        <Link href="/" className="w-fit font-semibold text-link hover:underline">
          Wróć do aplikacji
        </Link>
      </main>
    </div>
  );
}
