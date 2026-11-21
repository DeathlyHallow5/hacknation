"use client";

import { useQuery } from "@tanstack/react-query";
import { Check, CircleCheck, Play, TriangleAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { Guard, SearchInput } from "@/components/data/bits";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, RadioCards, Segmented, Slider } from "@/components/ui/form-controls";
import { Panel, Skeleton, Spinner } from "@/components/ui/misc";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { ScanCreateRequest } from "@/lib/api/types";
import { countLabel, fmtDate, fmtDuration, fmtNumber } from "@/lib/format";
import { CRITICALITY_LABEL, TARGET_TYPE_LABEL } from "@/lib/labels";
import { cn } from "@/lib/utils";

const STEPS = ["Cele", "Profil i bezpieczeństwo", "Termin", "Podsumowanie"];

/** Wizard steps as a row of numbered labels; the current one is semibold and underlined in the action colour. */
function Stepper({ step, onStep, maxStep }: { step: number; onStep: (s: number) => void; maxStep: number }) {
  return (
    <ol className="flex flex-wrap items-center gap-x-7 gap-y-1 border-b border-line" aria-label="Kroki kreatora">
      {STEPS.map((label, i) => {
        const done = i < step;
        const current = i === step;
        return (
          <li key={label}>
            <button
              type="button"
              disabled={i > maxStep}
              onClick={() => onStep(i)}
              aria-current={current ? "step" : undefined}
              className={cn(
                "-mb-px flex items-center gap-2 border-b-2 py-2.5 text-sm transition-colors disabled:cursor-not-allowed disabled:opacity-50",
                current ? "border-accent font-semibold text-ink" : "border-transparent text-ink-2 hover:text-ink",
              )}
            >
              <span
                className={cn(
                  "tabular grid size-6 place-items-center rounded-full border text-xs font-semibold",
                  current ? "border-ink bg-ink text-surface" : done ? "border-ink-2 text-ink" : "border-line-strong text-ink-2",
                )}
              >
                {done ? <Check className="size-3.5" strokeWidth={3} aria-hidden /> : i + 1}
              </span>
              {label}
              {done ? <span className="sr-only">(ukończony)</span> : null}
            </button>
          </li>
        );
      })}
    </ol>
  );
}

export function NewScanView() {
  const router = useRouter();
  const [step, setStep] = React.useState(0);
  const [maxStep, setMaxStep] = React.useState(0);
  // null = untouched: default to every non-excluded CIDR range.
  const [picked, setPicked] = React.useState<Set<string> | null>(null);
  const [filter, setFilter] = React.useState("");
  const [profileId, setProfileId] = React.useState("p-1");
  const [start, setStart] = React.useState<"now" | "window" | "test">("now");
  const [testSeconds, setTestSeconds] = React.useState(25);
  const [winStart, setWinStart] = React.useState("22:00");
  const [winEnd, setWinEnd] = React.useState("06:00");
  const [behaviour, setBehaviour] = React.useState<"pause_resume" | "stop">("pause_resume");
  const [name, setName] = React.useState(`Skan doraźny ${fmtDate(new Date().toISOString())}`);
  const [pending, setPending] = React.useState(false);

  const targets = useQuery({ queryKey: ["targets", "all"], queryFn: () => api.targets.list({ page_size: 500, sort: "-criticality_rank,value" }) });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: api.profiles.list });
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings.get });

  const defaultSelection = React.useMemo(
    () => new Set((targets.data?.items ?? []).filter((t) => !t.excluded && t.type === "cidr").map((t) => t.id)),
    [targets.data],
  );
  const selected = picked ?? defaultSelection;
  const setSelected = (next: Set<string> | ((prev: Set<string>) => Set<string>)) =>
    setPicked((prev) => (typeof next === "function" ? next(prev ?? defaultSelection) : next));

  const ids = [...selected].sort();
  const scanWindow = { start: winStart, end: winEnd, timezone: "Europe/Warsaw" };
  const estimate = useQuery({
    queryKey: ["estimate", ids.join(","), profileId, winStart, winEnd],
    queryFn: () => api.scans.estimate({ target_ids: ids, profile_id: profileId, window: scanWindow }),
    enabled: ids.length > 0,
    placeholderData: (p) => p,
  });

  const go = (s: number) => {
    setStep(s);
    setMaxStep((m) => Math.max(m, s));
  };
  const items = (targets.data?.items ?? []).filter((t) => !filter || t.value.includes(filter.toLowerCase()) || (t.name ?? "").toLowerCase().includes(filter.toLowerCase()));
  const profile = profiles.data?.find((p) => p.id === profileId);
  const est = estimate.data;

  const launch = async () => {
    setPending(true);
    const body: ScanCreateRequest = {
      name,
      target_ids: ids,
      profile_id: profileId,
      start: start === "window" ? "window" : "now",
      window: scanWindow,
      on_window_exceeded: behaviour,
      test_window_seconds: start === "test" ? testSeconds : null,
    };
    try {
      const run = await api.scans.create(body);
      toast.success(start === "window" ? `Zaplanowano skan #${run.number}` : `Uruchomiono skan #${run.number}`, {
        description: start === "window" ? `Rozpocznie się w oknie ${winStart}–${winEnd}.` : "Postęp możesz śledzić na żywo.",
      });
      router.push(`/scans/${run.id}`);
    } catch (e) {
      toast.error("Nie udało się uruchomić skanowania", { description: errorMessage(e) });
      setPending(false);
    }
  };

  return (
    <Container className="pb-12">
      <PageHeader back={{ href: "/scans", label: "Skanowania" }} title="Nowe skanowanie" />
      <div className="mb-6">
        <Stepper step={step} onStep={go} maxStep={maxStep} />
      </div>
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="grid gap-6">
          {step === 0 ? (
            <Panel
              title="Cele skanowania"
              actions={
                <div className="flex gap-2">
                  <Button size="sm" variant="ghost" onClick={() => setSelected(new Set((targets.data?.items ?? []).filter((t) => !t.excluded).map((t) => t.id)))}>
                    Zaznacz wszystkie
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
                    Wyczyść
                  </Button>
                </div>
              }
              flush
            >
              <div className="border-b border-line px-5 py-3">
                <SearchInput value={filter} onChange={setFilter} placeholder="Filtruj cele…" className="w-full sm:w-72" />
              </div>
              <ul className="scroll-quiet max-h-[28rem] divide-y divide-line overflow-y-auto">
                {items.map((t) => (
                  <li key={t.id}>
                    <label className={cn("flex items-center gap-3 px-5 py-3", t.excluded ? "cursor-not-allowed opacity-55" : "cursor-pointer hover:bg-surface-2")}>
                      <Checkbox
                        checked={selected.has(t.id)}
                        disabled={t.excluded}
                        onCheckedChange={(c) =>
                          setSelected((prev) => {
                            const next = new Set(prev);
                            if (c) next.add(t.id);
                            else next.delete(t.id);
                            return next;
                          })
                        }
                      />
                      <span className="grid min-w-0 flex-1 gap-0.5">
                        <span className="mono truncate font-medium">{t.value}</span>
                        <span className="truncate text-xs text-ink-2">
                          {t.name ?? TARGET_TYPE_LABEL[t.type]}
                          {t.excluded ? ", wykluczony ze skanowania" : ""}
                        </span>
                      </span>
                      <span className="tabular w-32 text-right text-sm text-ink-2">{t.type === "domain" ? "domena" : countLabel(t.address_count, ["adres", "adresy", "adresów"])}</span>
                      <span className="hidden w-20 text-right text-xs text-ink-2 md:inline">{CRITICALITY_LABEL[t.criticality]}</span>
                    </label>
                  </li>
                ))}
                {!targets.data ? (
                  <li className="grid gap-2 p-5">
                    <Skeleton className="h-8" />
                    <Skeleton className="h-8" />
                    <Skeleton className="h-8" />
                  </li>
                ) : null}
              </ul>
            </Panel>
          ) : null}

          {step === 1 ? (
            <Panel title="Profil skanowania" description="Profile edytujesz w zakładce Profile na stronie Skanowania.">
              <div className="grid gap-5">
                <RadioCards
                  columns={2}
                  value={profileId}
                  onValueChange={setProfileId}
                  options={(profiles.data ?? []).map((p) => ({
                    value: p.id,
                    title: p.name,
                    description: (
                      <>
                        {p.description}
                        <span className="mt-1.5 block text-ink">
                          {fmtNumber(p.rate_limit_rps)} zapytań/s, nmap <span className="mono">{p.nmap_timing}</span>, {countLabel(p.max_concurrency, ["wątek", "wątki", "wątków"])}
                        </span>
                      </>
                    ),
                  }))}
                />
                <section className="grid gap-2 border-t border-line pt-4 text-sm" aria-labelledby="safety-rules">
                  <h3 id="safety-rules" className="font-semibold">
                    Zasady bezpiecznego skanowania
                  </h3>
                  <ul className="grid list-disc gap-1 pl-5 text-ink-2 marker:text-ink-3">
                    <li>
                      Globalny limit: {fmtNumber(settings.data?.scan_safety.max_rate_rps ?? 500)} zapytań/s i{" "}
                      {countLabel(settings.data?.scan_safety.max_concurrency ?? 64, ["równoległe połączenie", "równoległe połączenia", "równoległych połączeń"])}; profil nie może go przekroczyć.
                    </li>
                    <li>
                      Skaner przedstawia się nagłówkiem User-Agent: <code className="mono text-ink">{settings.data?.scan_safety.user_agent ?? "CBI-AGH-ASI"}</code>
                    </li>
                    <li>Sygnatury wykonują tylko proste żądania GET/HEAD, bez logowania, formularzy i parametrów ataku.</li>
                    <li>
                      Adresy z listy wykluczeń (<span className="mono">{settings.data?.scan_safety.excluded_cidrs.join(", ") ?? "—"}</span>) są pomijane zawsze.
                    </li>
                  </ul>
                </section>
              </div>
            </Panel>
          ) : null}

          {step === 2 ? (
            <Panel title="Termin uruchomienia" description="Skan, który nie zdąży, wznowi się w kolejnym oknie od ostatniej podgrupy.">
              <div className="grid gap-5">
                <RadioCards
                  value={start}
                  onValueChange={setStart}
                  options={[
                    { value: "now", title: "Teraz", description: "Skan doraźny, uruchamiany od razu, bez czekania na okno." },
                    { value: "window", title: "W najbliższym oknie", description: `Start o ${winStart}, wstrzymanie o ${winEnd}.` },
                    { value: "test", title: "Teraz z oknem testowym", description: "Demonstracja: okno zamknie się po kilkudziesięciu sekundach, a skan wznowi się w kolejnym." },
                  ]}
                />
                {start === "test" ? (
                  <Field label={`Długość okna testowego: ${testSeconds} s`} hint="Po zamknięciu okna skan zapisze punkt kontrolny; kolejne okno otworzy się po 20 s.">
                    <Slider aria-label="Długość okna testowego w sekundach" min={10} max={60} step={5} value={[testSeconds]} onValueChange={([v]) => setTestSeconds(v)} />
                  </Field>
                ) : null}
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Początek okna" htmlFor="w-start">
                    <Input id="w-start" type="time" value={winStart} onChange={(e) => setWinStart(e.target.value)} />
                  </Field>
                  <Field label="Koniec okna" htmlFor="w-end" hint="Może przechodzić przez północ.">
                    <Input id="w-end" type="time" value={winEnd} onChange={(e) => setWinEnd(e.target.value)} />
                  </Field>
                </div>
                <Field label="Gdy skan nie zmieści się w oknie">
                  <Segmented
                    aria-label="Zachowanie po przekroczeniu okna"
                    value={behaviour}
                    onChange={setBehaviour}
                    options={[
                      { value: "pause_resume", label: "Wstrzymaj i wznów w kolejnym oknie" },
                      { value: "stop", label: "Zatrzymaj" },
                    ]}
                  />
                </Field>
              </div>
            </Panel>
          ) : null}

          {step === 3 ? (
            <Panel title="Podsumowanie">
              <div className="grid gap-5">
                <Field label="Nazwa skanowania" htmlFor="scan-name">
                  <Input id="scan-name" value={name} onChange={(e) => setName(e.target.value)} />
                </Field>
                {est ? (
                  <div className="grid gap-3">
                    {/* Only the warning gets a tinted box; "it fits" is the normal case and stays plain. */}
                    <div className={cn("flex items-start gap-3", !est.fits_window && "rounded-lg bg-unstable-soft p-4 contrast:border contrast:border-current")}>
                      {est.fits_window ? <CircleCheck className="mt-0.5 size-5 shrink-0 text-ink-2" aria-hidden /> : <TriangleAlert className="mt-0.5 size-5 shrink-0 text-unstable-ink" aria-hidden />}
                      <div className="grid gap-0.5">
                        <p className="font-semibold">{est.fits_window ? "Skan zmieści się w oknie" : `Skan potrzebuje ${countLabel(est.windows_needed, ["okna", "okien", "okien"])}`}</p>
                        <p className="text-sm text-ink-2">
                          Szacowany czas: {fmtDuration(est.est_duration_s)} przy {fmtNumber(est.rate_rps)} zapytaniach/s; okno trwa {fmtDuration(est.window_seconds)}.
                        </p>
                      </div>
                    </div>
                    <ul className="grid list-disc gap-1.5 pl-5 text-sm text-ink-2 marker:text-ink-3">
                      {est.notes.map((n) => (
                        <li key={n}>{n}</li>
                      ))}
                    </ul>
                    <p className="text-sm text-ink-2">W trybie demonstracyjnym przebieg jest przyspieszony i trwa około minuty.</p>
                  </div>
                ) : (
                  <Skeleton className="h-24" />
                )}
              </div>
            </Panel>
          ) : null}

          <div className="flex items-center justify-between gap-3">
            <Button variant="ghost" onClick={() => (step === 0 ? router.push("/scans") : go(step - 1))}>
              {step === 0 ? "Anuluj" : "Wstecz"}
            </Button>
            {step < 3 ? (
              <Button variant="primary" onClick={() => go(step + 1)} disabled={step === 0 && ids.length === 0}>
                Dalej: {STEPS[step + 1]}
              </Button>
            ) : (
              <Guard permission="scans:create">
                <Button variant="primary" size="lg" onClick={launch} disabled={pending || !ids.length || !name.trim()}>
                  {pending ? <Spinner /> : <Play />} {start === "window" ? "Zaplanuj skanowanie" : "Uruchom skanowanie"}
                </Button>
              </Guard>
            )}
          </div>
        </div>

        <aside className="sticky top-32 grid gap-4 rounded-xl border border-line bg-surface p-5" aria-label="Plan skanowania">
          <h2 className="font-semibold">Plan skanowania</h2>
          <dl className="grid gap-2.5 text-sm">
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Cele</dt>
              <dd className="tabular">{ids.length}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Adresy</dt>
              <dd className="tabular">{est ? fmtNumber(est.addresses) : "—"}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Szacowane aktywne hosty</dt>
              <dd className="tabular">{est ? `ok. ${fmtNumber(est.est_alive)}` : "—"}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Profil</dt>
              <dd className="text-right">{profile?.name ?? "—"}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Podgrupy</dt>
              <dd className="tabular">
                {est ? (
                  <>
                    {est.batches} × <span className="mono">/{est.batch_prefix}</span>
                  </>
                ) : (
                  "—"
                )}
              </dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Szacowany czas</dt>
              <dd>{est ? fmtDuration(est.est_duration_s) : "—"}</dd>
            </div>
            <div className="flex justify-between gap-3">
              <dt className="text-ink-2">Termin</dt>
              <dd className="text-right">{start === "now" ? "teraz" : start === "test" ? `teraz, okno ${testSeconds} s` : `okno ${winStart}–${winEnd}`}</dd>
            </div>
          </dl>
          {est ? (
            <div className="grid gap-1.5">
              <div className="flex justify-between text-xs text-ink-2">
                <span>Czas skanu względem okna</span>
                <span className="tabular">{Math.round((est.est_duration_s / (est.window_seconds || 1)) * 100)}%</span>
              </div>
              <div className="relative h-2 overflow-hidden rounded-full bg-surface-3">
                <div
                  className={cn("h-full rounded-full", est.fits_window ? "bg-data" : "bg-unstable")}
                  style={{ width: `${Math.min(100, (est.est_duration_s / (est.window_seconds || 1)) * 100)}%` }}
                />
              </div>
            </div>
          ) : null}
        </aside>
      </div>
    </Container>
  );
}
