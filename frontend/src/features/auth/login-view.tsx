"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import * as React from "react";
import { LogoMark } from "@/components/brand/logo";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/form-controls";
import { Spinner } from "@/components/ui/misc";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import { hilbertD2XY } from "@/lib/net";
import { DEMO_USERS } from "@/lib/session";

/** Decorative order-5 Hilbert curve: the address space as one continuous line, no fake data on it. */
function CurveArt() {
  const n = 32;
  const cell = 18;
  const path = Array.from({ length: n * n }, (_, d) => hilbertD2XY(n, d))
    .map(([x, y], i) => `${i ? "L" : "M"}${x * cell + cell / 2},${y * cell + cell / 2}`)
    .join(" ");
  return (
    <svg viewBox={`0 0 ${n * cell} ${n * cell}`} className="size-full" aria-hidden preserveAspectRatio="xMidYMid slice">
      <path d={path} fill="none" stroke="var(--chrome-line)" strokeWidth="1.4" />
    </svg>
  );
}

export function LoginView() {
  const params = useSearchParams();
  const next = params.get("next") || "/";
  const [login, setLogin] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [error, setError] = React.useState<string | null>(null);
  const [pending, setPending] = React.useState<string | null>(null);
  const { data: meta } = useQuery({ queryKey: ["meta"], queryFn: api.meta, staleTime: Infinity });

  const doLogin = async (l: string, p: string, key: string) => {
    setError(null);
    setPending(key);
    try {
      await api.auth.login({ login: l, password: p });
      window.location.href = next.startsWith("/") ? next : "/";
    } catch (e) {
      setError(errorMessage(e));
      setPending(null);
    }
  };

  return (
    <div className="grid min-h-dvh bg-canvas lg:grid-cols-[1.15fr_1fr]">
      <aside className="relative hidden overflow-hidden bg-chrome text-chrome-ink lg:flex lg:flex-col">
        {/* One texture: the address space as a single Hilbert line. Hidden in the contrast theme. */}
        <div className="absolute inset-0 opacity-50 contrast:hidden">
          <CurveArt />
        </div>
        <div className="relative flex items-center gap-2.5 p-10">
          <LogoMark className="text-chrome-ink" />
          <span className="text-lg font-extrabold tracking-tight">CBI AGH</span>
        </div>
        <div className="relative mt-auto max-w-xl p-10 pb-14">
          <h1 className="text-[clamp(2.5rem,1.2rem+3vw,4rem)] leading-[1.02] font-extrabold tracking-[-0.03em] text-balance">Attack Surface Intelligence.</h1>
          <p className="mt-5 max-w-md text-lg leading-relaxed text-balance text-chrome-ink-2">Ciągły monitoring powierzchni ataku sieci uczelni.</p>
        </div>
      </aside>

      <main className="flex flex-col">
        <div className="flex items-center gap-2.5 bg-chrome p-5 text-chrome-ink lg:hidden">
          <LogoMark className="text-chrome-ink" />
          <span className="font-extrabold">CBI AGH</span>
          <span className="text-sm text-chrome-ink-2">Attack Surface Intelligence</span>
        </div>
        <div className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center gap-8 px-6 py-12">
          <div className="grid gap-2">
            <h2 className="text-2xl font-semibold">Zaloguj się</h2>
            <p className="text-sm text-ink-2">Użyj konta służbowego Centrum Bezpieczeństwa Informacji.</p>
          </div>
          <form
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              void doLogin(login, password, "form");
            }}
          >
            <Field label="Login lub e-mail" htmlFor="login">
              <Input id="login" autoComplete="username" value={login} onChange={(e) => setLogin(e.target.value)} className="h-11" required />
            </Field>
            <Field label="Hasło" htmlFor="password">
              <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} className="h-11" required />
            </Field>
            {error ? (
              <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm font-semibold text-danger">
                {error}
              </p>
            ) : null}
            <Button type="submit" variant="primary" size="lg" disabled={pending !== null}>
              {pending === "form" ? <Spinner /> : null} Zaloguj się
            </Button>
          </form>

          {/* Demo accounts: a plain list under a rule, not a card of bordered buttons. */}
          {meta && meta.mode !== "proxy" ? (
            <section className="grid gap-2 border-t border-line pt-6" aria-labelledby="demo-title">
              <div className="grid gap-0.5">
                <h3 id="demo-title" className="text-sm font-semibold">
                  Tryb demonstracyjny
                </h3>
                <p className="text-sm text-ink-2">Wejdź jako jedna z czterech ról, aby sprawdzić rozgraniczenie uprawnień.</p>
              </div>
              <ul className="divide-y divide-line">
                {DEMO_USERS.map((u) => (
                  <li key={u.login}>
                    <button
                      type="button"
                      disabled={pending !== null}
                      onClick={() => doLogin(u.login, "demo", u.login)}
                      className="group flex w-full items-center justify-between gap-3 rounded-sm py-2.5 text-left text-sm disabled:opacity-60"
                    >
                      <span>
                        <span className="font-semibold group-hover:text-link group-hover:underline">{u.role}:</span>{" "}
                        <span className="text-ink-2">
                          {u.name}, {u.hint}
                        </span>
                      </span>
                      {pending === u.login ? <Spinner /> : null}
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </div>
        <footer className="flex flex-wrap gap-x-5 gap-y-1 px-6 py-5 text-sm text-ink-2">
          <span>© 2026 Centrum Bezpieczeństwa Informacji AGH</span>
          <Link href="/dostepnosc" className="font-semibold text-link hover:underline">
            Deklaracja dostępności
          </Link>
        </footer>
      </main>
    </div>
  );
}
