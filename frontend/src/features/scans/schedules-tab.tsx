"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Pencil, Plus, Trash2 } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { EmptyState, ErrorState, Guard, SearchInput } from "@/components/data/bits";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Segmented, Switch } from "@/components/ui/form-controls";
import { Skeleton } from "@/components/ui/misc";
import { ConfirmDialog, Sheet, SheetBody, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { ApiError, errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Schedule, ScheduleInput } from "@/lib/api/types";
import { fmtNumber, fmtSmart } from "@/lib/format";
import { WEEKDAYS, WEEKDAYS_LONG } from "@/lib/labels";
import { isWithinWindow, nextScheduleRun } from "@/lib/schedule";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

function describe(s: Pick<Schedule, "frequency" | "cron" | "days">) {
  if (s.frequency === "cron") return `cron: ${s.cron}`;
  if (s.days.length === 7) return "codziennie";
  if (s.frequency === "weekly" && s.days.length === 1) return `co tydzień, ${WEEKDAYS_LONG[s.days[0] - 1].toLowerCase()}`;
  return s.days.map((d) => WEEKDAYS[d - 1]).join(", ");
}

/** Create (schedule = null) or edit a schedule. Lives inside SheetContent, so it starts fresh on every opening. */
function ScheduleForm({ schedule, onClose }: { schedule: Schedule | null; onClose: () => void }) {
  const qc = useQueryClient();
  const can = useCan();
  const targets = useQuery({ queryKey: ["targets", "all"], queryFn: () => api.targets.list({ page_size: 500, sort: "-criticality_rank,value" }) });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: api.profiles.list });
  const isNew = schedule === null;
  const [name, setName] = React.useState(schedule?.name ?? "");
  const [enabled, setEnabled] = React.useState(schedule?.enabled ?? true);
  const [targetIds, setTargetIds] = React.useState<Set<string>>(() => new Set(schedule?.target_ids ?? []));
  const [profileId, setProfileId] = React.useState(schedule?.profile_id ?? "p-1");
  const [start, setStart] = React.useState(schedule?.window.start ?? "22:00");
  const [end, setEnd] = React.useState(schedule?.window.end ?? "06:00");
  const [frequency, setFrequency] = React.useState<Schedule["frequency"]>(schedule?.frequency ?? "daily");
  const [days, setDays] = React.useState<number[]>(schedule?.days ?? [1, 2, 3, 4, 5, 6, 7]);
  const [cron, setCron] = React.useState(schedule?.cron ?? "0 22 * * 1-5");
  const [behaviour, setBehaviour] = React.useState<Schedule["on_window_exceeded"]>(schedule?.on_window_exceeded ?? "pause_resume");
  const [filter, setFilter] = React.useState("");
  const [errors, setErrors] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [confirmDelete, setConfirmDelete] = React.useState(false);
  const editable = can(isNew ? "schedules:create" : "schedules:update");

  const allTargets = targets.data?.items ?? [];
  const shown = allTargets.filter((t) => !filter || t.value.includes(filter.toLowerCase()) || (t.name ?? "").toLowerCase().includes(filter.toLowerCase()));
  const addresses = allTargets.filter((t) => targetIds.has(t.id) && !t.excluded).reduce((n, t) => n + t.address_count, 0);
  const runDays = frequency === "cron" ? [1, 2, 3, 4, 5, 6, 7] : frequency === "weekly" ? days.slice(0, 1) : days;
  // Same rules the API uses for `next_run_at`, so the preview matches the card after saving.
  const nextRun = frequency !== "cron" && !days.length ? null : nextScheduleRun({ frequency, days: runDays, cron, window: { start } });
  const outsideWindow = frequency === "cron" && nextRun !== null && !isWithinWindow(nextRun, start, end);
  const problems = [
    !name.trim() ? "Podaj nazwę harmonogramu." : null,
    !targetIds.size ? "Wybierz co najmniej jeden cel." : null,
    frequency !== "cron" && !days.length ? "Wybierz co najmniej jeden dzień tygodnia." : null,
    frequency === "cron" && !nextRun ? "Wyrażenie cron jest niepoprawne albo nie wypada w ciągu najbliższego roku." : null,
  ].filter(Boolean) as string[];

  const save = async () => {
    setSaving(true);
    setErrors(null);
    const body: ScheduleInput = {
      name: name.trim(),
      enabled,
      target_ids: [...targetIds],
      profile_id: profileId,
      window: { start, end, timezone: "Europe/Warsaw" },
      days: runDays,
      frequency,
      cron: frequency === "cron" ? cron.trim() : null,
      on_window_exceeded: behaviour,
    };
    try {
      if (isNew) await api.schedules.create(body);
      else await api.schedules.update(schedule.id, body);
      qc.invalidateQueries({ queryKey: ["schedules"] });
      qc.invalidateQueries({ queryKey: ["dashboard-summary"] });
      toast.success(isNew ? "Utworzono harmonogram" : "Zapisano harmonogram", { description: name.trim() });
      onClose();
    } catch (e) {
      setErrors(e instanceof ApiError ? e.message : errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!schedule) return;
    try {
      await api.schedules.remove(schedule.id);
      qc.invalidateQueries({ queryKey: ["schedules"] });
      toast.success("Usunięto harmonogram", { description: schedule.name });
      onClose();
    } catch (e) {
      toast.error("Nie udało się usunąć", { description: errorMessage(e) });
    }
  };

  const toggleDay = (d: number) =>
    setDays((prev) => (frequency === "weekly" ? [d] : prev.includes(d) ? prev.filter((x) => x !== d) : [...prev, d].sort()));

  return (
    <>
      <SheetHeader>
        <SheetTitle>{isNew ? "Nowy harmonogram" : schedule.name}</SheetTitle>
        <SheetDescription>Cykliczne skanowanie w oknie czasowym. Jeśli skan nie zdąży, zostanie wstrzymany i wznowiony w kolejnym oknie od ostatniej podgrupy.</SheetDescription>
      </SheetHeader>
      <SheetBody className="grid content-start gap-5">
        <Field label="Nazwa" htmlFor="sch-name">
          <Input id="sch-name" disabled={!editable} value={name} onChange={(e) => setName(e.target.value)} placeholder="np. Nocny przegląd laboratoriów" />
        </Field>
        <label className="flex items-center justify-between gap-3 rounded-lg border border-line p-3">
          <span className="text-sm font-semibold">Harmonogram aktywny</span>
          <Switch checked={enabled} disabled={!editable} onCheckedChange={setEnabled} />
        </label>

        <Field label={`Cele (${targetIds.size}, ${fmtNumber(addresses)} adresów)`}>
          <div className="grid gap-2 rounded-lg border border-line p-2">
            <SearchInput value={filter} onChange={setFilter} placeholder="Filtruj cele…" />
            <ul className="scroll-quiet max-h-48 overflow-y-auto">
              {shown.map((t) => (
                <li key={t.id}>
                  <label className={cn("flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm", t.excluded ? "opacity-50" : "cursor-pointer hover:bg-surface-2")}>
                    <Checkbox
                      checked={targetIds.has(t.id)}
                      disabled={!editable || t.excluded}
                      onCheckedChange={(c) =>
                        setTargetIds((prev) => {
                          const next = new Set(prev);
                          if (c) next.add(t.id);
                          else next.delete(t.id);
                          return next;
                        })
                      }
                    />
                    <span className="mono truncate">{t.value}</span>
                    <span className="truncate text-xs text-ink-2">{t.excluded ? "wykluczony" : (t.name ?? "")}</span>
                  </label>
                </li>
              ))}
              {!targets.data ? <Skeleton className="h-24" /> : null}
            </ul>
          </div>
        </Field>

        <Field label="Profil skanowania">
          <SimpleSelect aria-label="Profil skanowania" disabled={!editable} value={profileId} onChange={(v) => setProfileId(v || "p-1")} options={(profiles.data ?? []).map((p) => ({ value: p.id, label: p.name }))} />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Początek okna" htmlFor="sch-start">
            <Input id="sch-start" type="time" disabled={!editable} value={start} onChange={(e) => setStart(e.target.value)} />
          </Field>
          <Field label="Koniec okna" htmlFor="sch-end" hint="Okno może przechodzić przez północ.">
            <Input id="sch-end" type="time" disabled={!editable} value={end} onChange={(e) => setEnd(e.target.value)} />
          </Field>
        </div>

        <Field label="Częstotliwość">
          <Segmented
            aria-label="Częstotliwość"
            value={frequency}
            onChange={(f) => {
              if (!editable) return;
              setFrequency(f);
              if (f === "weekly") setDays((prev) => prev.slice(0, 1).length ? prev.slice(0, 1) : [6]);
            }}
            options={[
              { value: "daily", label: "W wybrane dni" },
              { value: "weekly", label: "Raz w tygodniu" },
              { value: "cron", label: "Wyrażenie cron" },
            ]}
          />
        </Field>
        {frequency === "cron" ? (
          <Field label="Wyrażenie cron" htmlFor="sch-cron" hint="Pola: minuta, godzina, dzień miesiąca, miesiąc, dzień tygodnia. Np. „0 10,13,15 * * 1-5” — o 10, 13 i 15 w dni robocze.">
            <Input id="sch-cron" className="mono" disabled={!editable} value={cron} onChange={(e) => setCron(e.target.value)} />
          </Field>
        ) : (
          <Field label={frequency === "weekly" ? "Dzień tygodnia" : "Dni tygodnia"}>
            <div className="flex flex-wrap gap-1.5">
              {WEEKDAYS.map((d, i) => {
                const on = days.includes(i + 1);
                return (
                  <button
                    key={d}
                    type="button"
                    disabled={!editable}
                    aria-pressed={on}
                    aria-label={WEEKDAYS_LONG[i]}
                    onClick={() => toggleDay(i + 1)}
                    className={cn(
                      "h-9 w-11 rounded-lg border text-sm font-semibold transition-colors disabled:cursor-not-allowed",
                      on ? "border-accent bg-accent/12 text-ink" : "border-line-strong text-ink-2 hover:border-ink-3",
                    )}
                  >
                    {d}
                  </button>
                );
              })}
            </div>
          </Field>
        )}
        {nextRun ? (
          <div className="grid gap-1 rounded-lg bg-surface-2 px-3 py-2.5 text-sm text-ink-2" aria-live="polite">
            <p className="flex items-center gap-2">
              <CalendarClock className="size-4 shrink-0 text-link" aria-hidden />
              <span>
                {enabled ? "Najbliższe uruchomienie: " : "Po włączeniu najbliższe uruchomienie: "}
                <span className="font-semibold text-ink">{fmtSmart(nextRun.toISOString())}</span>
              </span>
            </p>
            {outsideWindow ? (
              <p className="pl-6">
                Ten termin wypada poza oknem {start}–{end}, więc skan rozpocznie się dopiero po otwarciu okna.
              </p>
            ) : null}
          </div>
        ) : null}

        <Field label="Gdy skan nie zmieści się w oknie">
          <Segmented
            aria-label="Zachowanie po przekroczeniu okna"
            value={behaviour}
            onChange={(b) => editable && setBehaviour(b)}
            options={[
              { value: "pause_resume", label: "Wstrzymaj i wznów w kolejnym oknie" },
              { value: "stop", label: "Zatrzymaj" },
            ]}
          />
        </Field>

        {problems.length || errors ? (
          <div className="grid gap-1 rounded-lg bg-danger-soft p-3 text-sm text-danger" role="alert">
            {[...problems, ...(errors ? [errors] : [])].map((p) => (
              <span key={p}>{p}</span>
            ))}
          </div>
        ) : null}
      </SheetBody>
      <SheetFooter className="justify-between">
        {!isNew ? (
          <Guard permission="schedules:delete">
            <Button variant="danger" onClick={() => setConfirmDelete(true)}>
              <Trash2 /> Usuń
            </Button>
          </Guard>
        ) : (
          <span />
        )}
        <div className="flex gap-2">
          <Button variant="secondary" onClick={onClose}>
            Anuluj
          </Button>
          <Guard permission={isNew ? "schedules:create" : "schedules:update"}>
            <Button variant="primary" onClick={save} disabled={saving || problems.length > 0}>
              {isNew ? "Utwórz harmonogram" : "Zapisz harmonogram"}
            </Button>
          </Guard>
        </div>
      </SheetFooter>
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`Usunąć harmonogram „${schedule?.name}”?`}
        description="Kolejne skanowania z tego harmonogramu nie zostaną uruchomione. Historia wcześniejszych przebiegów pozostanie. Tej operacji nie można cofnąć."
        confirmLabel="Usuń harmonogram"
        onConfirm={() => {
          setConfirmDelete(false);
          void remove();
        }}
      />
    </>
  );
}

export function SchedulesTab() {
  const can = useCan();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["schedules"], queryFn: api.schedules.list });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: api.profiles.list });
  // { schedule: null } = new; null = closed. Keep the last value for the closing animation.
  const [editing, setEditing] = React.useState<{ schedule: Schedule | null } | null>(null);
  const [last, setLast] = React.useState(editing);
  if (editing && editing !== last) setLast(editing);

  if (q.isError) return <ErrorState error={q.error} onRetry={() => q.refetch()} />;
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-ink-2">Harmonogramy uruchamiają skanowania cyklicznie w określonych oknach czasowych, np. nocą, aby ograniczyć wpływ na użytkowników sieci.</p>
        <Guard permission="schedules:create">
          <Button variant="primary" onClick={() => setEditing({ schedule: null })}>
            <Plus /> Nowy harmonogram
          </Button>
        </Guard>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        {(q.data ?? []).map((s) => (
          <article key={s.id} className={cn("grid content-start gap-4 rounded-xl border border-line bg-surface p-5", !s.enabled && "opacity-70")}>
            <div className="flex items-start justify-between gap-3">
              <div className="grid gap-1">
                <h3 className="font-bold">{s.name}</h3>
                <p className="text-sm text-ink-2">Profil: {profiles.data?.find((p) => p.id === s.profile_id)?.name ?? "—"}</p>
              </div>
              <Switch
                aria-label={`Włącz harmonogram ${s.name}`}
                checked={s.enabled}
                disabled={!can("schedules:update")}
                onCheckedChange={async (c) => {
                  try {
                    await api.schedules.update(s.id, { enabled: c });
                    qc.invalidateQueries({ queryKey: ["schedules"] });
                    toast.success(c ? "Włączono harmonogram" : "Wyłączono harmonogram", { description: s.name });
                  } catch (e) {
                    toast.error("Nie udało się zmienić", { description: errorMessage(e) });
                  }
                }}
              />
            </div>
            <div className="flex items-center gap-3 rounded-lg bg-surface-2 p-3">
              <CalendarClock className="size-5 text-link" aria-hidden />
              <div className="grid">
                <span className="tabular text-lg font-extrabold">
                  {s.window.start}–{s.window.end}
                </span>
                <span className="text-xs text-ink-2">{describe(s)}</span>
              </div>
            </div>
            <dl className="grid gap-1.5 text-sm">
              <div className="flex justify-between gap-3">
                <dt className="text-ink-2">Następne uruchomienie</dt>
                <dd className="font-semibold">{s.enabled ? fmtSmart(s.next_run_at) : "wyłączony"}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-ink-2">Po przekroczeniu okna</dt>
                <dd className="font-semibold">{s.on_window_exceeded === "pause_resume" ? "wstrzymaj i wznów" : "zatrzymaj"}</dd>
              </div>
              <div className="flex justify-between gap-3">
                <dt className="text-ink-2">Cele</dt>
                <dd className="font-semibold">{s.target_ids.length}</dd>
              </div>
            </dl>
            <Button
              size="sm"
              onClick={() => setEditing({ schedule: s })}
              aria-label={can("schedules:update") ? `Edytuj harmonogram ${s.name}` : `Szczegóły harmonogramu ${s.name}`}
            >
              <Pencil /> {can("schedules:update") ? "Edytuj" : "Szczegóły"}
            </Button>
          </article>
        ))}
        {!q.data ? [0, 1, 2].map((i) => <Skeleton key={i} className="h-72 rounded-xl" />) : null}
      </div>
      {q.data && !q.data.length ? (
        <EmptyState
          title="Brak harmonogramów"
          description="Utwórz harmonogram, aby skanowanie uruchamiało się samo w wybranych oknach czasowych."
          action={can("schedules:create") ? <Button variant="primary" onClick={() => setEditing({ schedule: null })}><Plus /> Nowy harmonogram</Button> : null}
        />
      ) : null}
      <Sheet open={Boolean(editing)} onOpenChange={(o) => !o && setEditing(null)}>
        <SheetContent>{last ? <ScheduleForm schedule={last.schedule} onClose={() => setEditing(null)} /> : null}</SheetContent>
      </Sheet>
    </div>
  );
}
