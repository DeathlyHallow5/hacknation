import Link from "next/link";
import { LogoMark } from "@/components/brand/logo";

export default function NotFound() {
  return (
    <div className="chrome-dots grid min-h-dvh place-items-center bg-chrome px-6 text-chrome-ink">
      <div className="grid max-w-md justify-items-center gap-4 text-center">
        <LogoMark className="size-12 text-chrome-ink" />
        <p className="mono text-sm text-chrome-ink-2">404</p>
        <h1 className="text-[1.75rem] leading-tight font-semibold">Nie ma takiej strony</h1>
        <p className="text-chrome-ink-2">Adres mógł się zmienić albo zasób został usunięty. Sprawdź adres lub wróć na pulpit.</p>
        <Link href="/" data-button="" className="rounded-lg bg-accent px-4 py-2 font-semibold text-accent-ink hover:bg-accent-hover">
          Wróć na pulpit
        </Link>
      </div>
    </div>
  );
}
