"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowRight, KeyRound, LogIn, UserRound } from "lucide-react";
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

/** Decorative order-5 Hilbert curve: the address space as one continuous line. */
function CurveArt() {
  const n = 32;
  const cell = 18;
  const pts = Array.from({ length: n * n }, (_, d) => hilbertD2XY(n, d));
  const path = pts.map(([x, y], i) => `${i ? "L" : "M"}${x * cell + cell / 2},${y * cell + cell / 2}`).join(" ");
  const lit = [37, 38, 39, 101, 102, 233, 234, 235, 236, 410, 411, 588, 589, 590, 777, 778, 901, 902, 903, 1001];
  return (
    <svg viewBox={`0 0 ${n * cell} ${n * cell}`} className="size-full" aria-hidden preserveAspectRatio="xMidYMid slice">
      <path d={path} fill="none" stroke="var(--chrome-line)" strokeWidth="1.4" />
      {lit.map((d) => {
        const [x, y] = pts[d];
        return <rect key={d} x={x * cell + 4} y={y * cell + 4} width={cell - 8} height={cell - 8} rx="2" fill={d % 3 === 0 ? "var(--map-new)" : d % 3 === 1 ? "var(--map-active)" : "var(--map-unstable)"} opacity="0.85" />;
      })}
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
      <aside className="chrome-dots relative hidden overflow-hidden bg-chrome text-chrome-ink lg:flex lg:flex-col">
        <div className="absolute inset-0 opacity-60 [mask-image:radial-gradient(70%_70%_at_70%_55%,black,transparent)]">
          <CurveArt />
        </div>
        <div className="relative flex items-center gap-2.5 p-10">
          <LogoMark className="text-chrome-ink" />
          <span className="text-lg font-extrabold tracking-tight">CBI AGH</span>
        </div>
        <div className="relative mt-auto max-w-xl p-10 pb-14">
          <h1 className="text-[clamp(2.5rem,1.2rem+3vw,4rem)] leading-[1.02] font-extrabold tracking-[-0.03em]">Attack Surface Intelligence.</h1>
          <p className="mt-5 max-w-md text-[1.0625rem] leading-relaxed text-chrome-ink-2">
            Ciągły monitoring powierzchni ataku sieci uczelni: aktywne hosty, usługi, technologie i zmiany między kolejnymi skanami.
          </p>
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
            <h2 className="text-2xl font-extrabold tracking-tight">Zaloguj się</h2>
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
              <div className="relative">
                <UserRound className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ink-3" aria-hidden />
                <Input id="login" autoComplete="username" value={login} onChange={(e) => setLogin(e.target.value)} className="h-11 pl-9" required />
              </div>
            </Field>
            <Field label="Hasło" htmlFor="password">
              <div className="relative">
                <KeyRound className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ink-3" aria-hidden />
                <Input
                  id="password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="h-11 pl-9"
                  required
                />
              </div>
            </Field>
            {error ? (
              <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm font-semibold text-danger">
                {error}
              </p>
            ) : null}
            <Button type="submit" variant="primary" size="lg" disabled={pending !== null}>
              {pending === "form" ? <Spinner /> : <LogIn />} Zaloguj się
            </Button>
          </form>

          {meta && meta.mode !== "proxy" ? (
            <section className="grid gap-3 rounded-xl border border-line bg-surface p-4" aria-labelledby="demo-title">
              <div className="grid gap-0.5">
                <h3 id="demo-title" className="text-sm font-bold">
                  Tryb demonstracyjny
                </h3>
                <p className="text-[0.8125rem] text-ink-2">Wejdź jako jedna z czterech ról, aby sprawdzić rozgraniczenie uprawnień.</p>
              </div>
              <div className="grid gap-1.5">
                {DEMO_USERS.map((u) => (
                  <button
                    key={u.login}
                    type="button"
                    disabled={pending !== null}
                    onClick={() => doLogin(u.login, "demo", u.login)}
                    className="group flex items-center gap-3 rounded-lg border border-line px-3 py-2.5 text-left transition-colors hover:border-accent hover:bg-surface-2 disabled:opacity-60"
                  >
                    <span className="grid flex-1 leading-tight">
                      <span className="text-sm font-semibold">{u.role}</span>
                      <span className="text-[0.8125rem] text-ink-2">
                        {u.name}, {u.hint.toLowerCase()}
                      </span>
                    </span>
                    {pending === u.login ? <Spinner /> : <ArrowRight className="size-4 text-ink-3 transition-transform group-hover:translate-x-0.5 group-hover:text-link" aria-hidden />}
                  </button>
                ))}
              </div>
            </section>
          ) : null}
        </div>
        <footer className="flex flex-wrap gap-x-5 gap-y-1 px-6 py-5 text-[0.8125rem] text-ink-2">
          <span>© 2026 Centrum Bezpieczeństwa Informacji AGH</span>
          <Link href="/dostepnosc" className="font-semibold text-link hover:underline">
            Deklaracja dostępności
          </Link>
        </footer>
      </main>
    </div>
  );
}
