"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Send, Server } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard, ManualOverrideBadge, MonoValue, TagInput } from "@/components/data/bits";
import { ChangeChip, ConfidenceMeter, FindingStatusChip, ScoreMeter } from "@/components/data/status";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/form-controls";
import { Skeleton } from "@/components/ui/misc";
import { Sheet, SheetBody, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Evidence, Finding, FindingStatus } from "@/lib/api/types";
import { countLabel, fmtSmart } from "@/lib/format";
import { useApiMutation } from "@/lib/hooks";
import { FINDING_CATEGORY_LABEL, FINDING_STATUS_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";

function Highlighted({ text, highlight }: { text: string; highlight: string | null }) {
  if (!highlight) return <>{text}</>;
  const i = text.toLowerCase().indexOf(highlight.toLowerCase());
  if (i < 0) return <>{text}</>;
  return (
    <>
      {text.slice(0, i)}
      <mark className="rounded bg-accent/25 px-0.5 text-ink contrast:bg-accent contrast:text-black">{text.slice(i, i + highlight.length)}</mark>
      {text.slice(i + highlight.length)}
    </>
  );
}

export function EvidenceList({ items }: { items: Evidence[] }) {
  return (
    <ul className="grid gap-2">
      {items.map((e, i) => (
        <li key={i} className="rounded-lg bg-surface-2 p-3 contrast:border contrast:border-line">
          <div className="mb-1.5 text-xs text-ink-2">{e.label}</div>
          <code className="mono block text-sm leading-relaxed break-all whitespace-pre-wrap text-ink">
            <Highlighted text={e.snippet} highlight={e.highlight} />
          </code>
        </li>
      ))}
    </ul>
  );
}

const STATUS_OPTIONS = (Object.keys(FINDING_STATUS_LABEL) as FindingStatus[]).map((s) => ({ value: s, label: FINDING_STATUS_LABEL[s] }));
const ASSIGNEES = ["Anna Nowak", "Piotr Wiśniewski", "Katarzyna Zielińska", "Jan Kowalski"];

function EditForm({ f }: { f: Finding }) {
  const can = useCan();
  const editable = can("findings:update");
  const [status, setStatus] = React.useState<FindingStatus>(f.status);
  const [assignee, setAssignee] = React.useState(f.assignee ?? "");
  const [override, setOverride] = React.useState(f.score_override === null ? "" : String(f.score_override));
  const [tags, setTags] = React.useState(f.tags);
  const [notes, setNotes] = React.useState(f.notes ?? "");
  const dirty =
    status !== f.status ||
    assignee !== (f.assignee ?? "") ||
    override !== (f.score_override === null ? "" : String(f.score_override)) ||
    JSON.stringify(tags) !== JSON.stringify(f.tags) ||
    notes !== (f.notes ?? "");
  const save = useApiMutation(
    () =>
      api.findings.update(f.id, {
        status,
        assignee: assignee || null,
        score_override: override === "" ? null : Math.max(0, Math.min(100, Number(override))),
        tags,
        notes: notes || null,
      }),
    { success: "Zapisano zmiany w znalezisku", invalidate: [["findings"], ["finding", f.id], ["top-findings"]] },
  );
  return (
    <form
      className="grid gap-4"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate(undefined);
      }}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Status" aside={<ManualOverrideBadge override={f.manual_overrides.status} />}>
          <SimpleSelect value={status} onChange={(v) => setStatus((v || "open") as FindingStatus)} options={STATUS_OPTIONS} disabled={!editable} aria-label="Status znaleziska" />
        </Field>
        <Field label="Przypisano">
          <SimpleSelect
            value={assignee}
            onChange={setAssignee}
            allLabel="Nikt"
            options={ASSIGNEES.map((a) => ({ value: a, label: a }))}
            disabled={!editable}
            aria-label="Osoba odpowiedzialna"
          />
        </Field>
      </div>
      <Field
        label="Priorytet ustawiony ręcznie"
        hint={`Wyliczony automatycznie: ${f.score}. Zostaw puste, aby używać wartości wyliczonej.`}
        htmlFor="score-override"
        aside={<ManualOverrideBadge override={f.manual_overrides.score_override} />}
      >
        <Input id="score-override" type="number" min={0} max={100} value={override} onChange={(e) => setOverride(e.target.value)} disabled={!editable} className="w-32" />
      </Field>
      <Field label="Tagi" htmlFor="finding-tags">
        <TagInput id="finding-tags" value={tags} onChange={setTags} suggestions={["do-przeglądu", "zgłoszone-właścicielowi", "wyjątek", "kampania-2026"]} />
      </Field>
      <Field label="Notatki analityka" htmlFor="finding-notes" hint="Notatki są szyfrowane w bazie danych.">
        <Textarea id="finding-notes" value={notes} onChange={(e) => setNotes(e.target.value)} disabled={!editable} placeholder="Np. potwierdzone z właścicielem, panel zostanie ukryty za VPN do 30.11." />
      </Field>
      <div className="flex items-center justify-end gap-2">
        <Guard permission="findings:update">
          <Button type="submit" variant="primary" disabled={!dirty || save.isPending}>
            Zapisz zmiany
          </Button>
        </Guard>
      </div>
    </form>
  );
}

export function FindingDrawer({ id, onOpenChange }: { id: string | null; onOpenChange: (open: boolean) => void }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api.findings.get(id!), enabled: Boolean(id) });
  const f = q.data;
  const [sending, setSending] = React.useState(false);
  const sendDD = async () => {
    if (!f) return;
    setSending(true);
    try {
      const r = await api.findings.defectdojo({ ids: [f.id], as: "finding" });
      toast.success("Wysłano do DefectDojo", { description: `Utworzono finding informacyjny (${r.exported})` });
      qc.invalidateQueries({ queryKey: ["finding", f.id] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    } catch (e) {
      toast.error("Nie udało się wysłać do DefectDojo", { description: errorMessage(e) });
    } finally {
      setSending(false);
    }
  };

  return (
    <Sheet open={Boolean(id)} onOpenChange={onOpenChange}>
      <SheetContent width="lg">
        <SheetHeader>
          {f ? (
            <>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
                <ChangeChip state={f.change} measurements={f.measurements} />
                <FindingStatusChip value={f.status} />
                <span className="text-sm text-ink-2">{FINDING_CATEGORY_LABEL[f.category]}</span>
              </div>
              <SheetTitle className="mt-1">{f.title}</SheetTitle>
              <SheetDescription asChild>
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <MonoValue value={`${f.ip}${f.port ? `:${f.port}` : ""}`} className="font-medium text-ink" />
                  {f.hostname ? <span className="truncate">{f.hostname}</span> : null}
                </div>
              </SheetDescription>
            </>
          ) : (
            <>
              <SheetTitle className="sr-only">Szczegóły znaleziska</SheetTitle>
              <SheetDescription className="sr-only">Wczytywanie</SheetDescription>
              <Skeleton className="h-6 w-64" />
              <Skeleton className="h-4 w-40" />
            </>
          )}
        </SheetHeader>
        <SheetBody>
          {q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : null}
          {f ? (
            <div className="grid gap-7">
              <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                <div className="grid content-start gap-1">
                  <dt className="text-xs text-ink-2">Priorytet</dt>
                  <dd>
                    <ScoreMeter score={f.score_override ?? f.score} overridden={f.score_override !== null} />
                  </dd>
                </div>
                <div className="grid content-start gap-1">
                  <dt className="text-xs text-ink-2">Pewność</dt>
                  <dd>
                    <ConfidenceMeter value={f.confidence} compact />
                  </dd>
                </div>
                <div className="grid content-start gap-1">
                  <dt className="text-xs text-ink-2">Pomiary</dt>
                  <dd className="tabular text-sm">
                    {f.measurements.responded}/{f.measurements.total} odpowiedzi
                  </dd>
                </div>
                <div className="grid content-start gap-1">
                  <dt className="text-xs text-ink-2">Pierwsze wykrycie</dt>
                  <dd className="text-sm">{fmtSmart(f.first_seen)}</dd>
                  <dd className="text-xs text-ink-2">
                    ostatnio {fmtSmart(f.last_seen)}, w {countLabel(f.occurrences, ["skanie", "skanach", "skanach"])}
                  </dd>
                </div>
              </dl>

              <section className="grid gap-2.5">
                <h3 className="text-sm font-semibold">Dowody</h3>
                <EvidenceList items={f.evidence} />
                {f.signature_name ? (
                  <p className="text-sm text-ink-2">
                    Dopasowana sygnatura: <span className="font-semibold text-ink">{f.signature_name}</span>
                  </p>
                ) : null}
              </section>

              <section className="grid gap-2.5">
                <h3 className="text-sm font-semibold">Dlaczego taki priorytet?</h3>
                <ul className="grid gap-1.5 rounded-lg border border-line p-3 text-sm">
                  {f.score_breakdown.map((b) => (
                    <li key={b.factor} className="flex items-center justify-between gap-3">
                      <span>{b.factor}</span>
                      <span className="tabular">+{b.points}</span>
                    </li>
                  ))}
                  <li className="mt-1 flex items-center justify-between gap-3 border-t border-line pt-2 font-semibold">
                    <span>Razem (maks. 99)</span>
                    <span className="tabular">{f.score}</span>
                  </li>
                </ul>
              </section>

              {f.technologies.length ? (
                <section className="grid gap-1.5">
                  <h3 className="text-sm font-semibold">Technologie</h3>
                  <p className="text-sm text-ink">{f.technologies.join(", ")}</p>
                </section>
              ) : null}

              <section className="grid gap-3 border-t border-line pt-6">
                <h3 className="text-sm font-semibold">Ocena i obsługa</h3>
                <EditForm key={f.id + JSON.stringify(f.manual_overrides)} f={f} />
              </section>

              {f.defectdojo ? (
                <p className="rounded-lg bg-surface-2 px-3 py-2.5 text-sm">
                  Wysłano do DefectDojo {fmtSmart(f.defectdojo.exported_at)} jako finding #{f.defectdojo.finding_id}.{" "}
                  <a href={f.defectdojo.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-semibold text-link hover:underline">
                    Otwórz <ExternalLink className="size-3.5" aria-hidden />
                  </a>
                </p>
              ) : null}
            </div>
          ) : !q.isError ? (
            <div className="grid gap-3">
              <Skeleton className="h-16" />
              <Skeleton className="h-28" />
              <Skeleton className="h-40" />
            </div>
          ) : null}
        </SheetBody>
        {f ? (
          <SheetFooter className="justify-between">
            <Button asChild variant="ghost">
              <Link href={`/assets/${f.host_id}`}>
                <Server /> Otwórz host
              </Link>
            </Button>
            <Guard permission="findings:defectdojo">
              <Button variant="secondary" onClick={sendDD} disabled={sending}>
                <Send /> {f.defectdojo ? "Wyślij ponownie do DefectDojo" : "Wyślij do DefectDojo"}
              </Button>
            </Guard>
          </SheetFooter>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
