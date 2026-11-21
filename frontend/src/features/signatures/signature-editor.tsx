"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, CircleX, Copy, FlaskConical, Plus, Save, ShieldAlert, ShieldCheck, Trash2, X } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import YAML from "yaml";
import { ErrorState, Guard, SearchInput, TagInput, useDebouncedValue } from "@/components/data/bits";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Segmented, Slider, Switch, Textarea } from "@/components/ui/form-controls";
import { Chip, Panel, Skeleton, Spinner } from "@/components/ui/misc";
import { ConfirmDialog } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { categoryLabel } from "@/features/signatures/signatures-view";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { FindingCategory, Signature, SignatureCondition, SignatureConditionType, SignatureInput, SignatureTestResult } from "@/lib/api/types";
import { fmtRelative } from "@/lib/format";
import { CONDITION_OP_LABEL, CONDITION_TYPE_LABEL, FINDING_CATEGORY_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

const CATEGORIES: Signature["category"][] = ["technology", ...(Object.keys(FINDING_CATEGORY_LABEL) as FindingCategory[])];
const OPS: SignatureCondition["op"][] = ["exists", "equals", "contains", "regex"];

const EMPTY: SignatureInput = {
  name: "",
  description: "",
  category: "technology",
  technology: null,
  score_weight: 10,
  enabled: true,
  match: { operator: "and", conditions: [{ type: "header", name: "Server", op: "contains", value: "" }] },
  tags: [],
};

/** Mirror of the server-side safety rules, for instant feedback. */
function localSafety(sig: SignatureInput): string[] {
  const issues: string[] = [];
  if (sig.name.trim().length < 3) issues.push("Nazwa musi mieć co najmniej 3 znaki.");
  if (!sig.match.conditions.length) issues.push("Dodaj co najmniej jeden warunek.");
  sig.match.conditions.forEach((c, i) => {
    const n = i + 1;
    if (c.type === "path") {
      const p = c.path ?? "";
      if (!p.startsWith("/")) issues.push(`Warunek ${n}: ścieżka musi zaczynać się od „/”.`);
      if (p.includes("?")) issues.push(`Warunek ${n}: bez parametrów zapytania — tylko proste GET.`);
      if (/(\.\.|[\s'"<>;`]|\bunion\b|\bselect\b)/i.test(p)) issues.push(`Warunek ${n}: znaki typowe dla ataku są niedozwolone.`);
      if (/(pass(word)?|pwd|token|login|user(name)?)=/i.test(p)) issues.push(`Warunek ${n}: ścieżka nie może przekazywać danych logowania.`);
    }
    if ((c.type === "header" || c.type === "cookie") && !/^[A-Za-z0-9_.\-]+$/.test(c.name ?? "")) issues.push(`Warunek ${n}: podaj nazwę ${c.type === "header" ? "nagłówka" : "ciasteczka"}.`);
    for (const re of [c.op === "regex" ? c.value : null, c.extract]) {
      if (!re) continue;
      try {
        new RegExp(re);
      } catch {
        issues.push(`Warunek ${n}: niepoprawne wyrażenie regularne.`);
      }
    }
  });
  return issues;
}

function ConditionRow({ c, index, onChange, onRemove, readOnly }: { c: SignatureCondition; index: number; onChange: (c: SignatureCondition) => void; onRemove: () => void; readOnly: boolean }) {
  const needsName = c.type === "header" || c.type === "cookie";
  return (
    <li className="grid gap-3 rounded-xl border border-line bg-surface-2 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-bold text-ink-2">Warunek {index + 1}</span>
        {!readOnly ? (
          <Button size="icon-sm" variant="ghost" aria-label={`Usuń warunek ${index + 1}`} onClick={onRemove}>
            <X />
          </Button>
        ) : null}
      </div>
      <div className="grid gap-2 sm:grid-cols-[11rem_1fr]">
        <SimpleSelect
          aria-label="Typ warunku"
          disabled={readOnly}
          value={c.type}
          onChange={(v) => onChange({ ...c, type: (v || "header") as SignatureConditionType, op: v === "favicon_hash" ? "equals" : v === "version" ? "regex" : c.op })}
          options={(Object.keys(CONDITION_TYPE_LABEL) as SignatureConditionType[]).map((t) => ({ value: t, label: CONDITION_TYPE_LABEL[t] }))}
        />
        <div className="grid gap-2 sm:grid-cols-[1fr_10rem]">
          {needsName ? (
            <Input aria-label="Nazwa" disabled={readOnly} className="mono" value={c.name ?? ""} onChange={(e) => onChange({ ...c, name: e.target.value })} placeholder={c.type === "header" ? "np. X-Powered-By" : "np. PHPSESSID"} />
          ) : c.type === "path" ? (
            <Input aria-label="Ścieżka" disabled={readOnly} className="mono" value={c.path ?? ""} onChange={(e) => onChange({ ...c, path: e.target.value })} placeholder="/admin/" />
          ) : (
            <span className="hidden sm:block" />
          )}
          {c.type === "path" ? (
            <Input
              aria-label="Oczekiwany kod odpowiedzi"
              disabled={readOnly}
              type="number"
              value={c.expect_status ?? ""}
              onChange={(e) => onChange({ ...c, expect_status: e.target.value ? Number(e.target.value) : null })}
              placeholder="kod, np. 200"
            />
          ) : c.type !== "favicon_hash" && c.type !== "version" ? (
            <SimpleSelect aria-label="Operator" disabled={readOnly} value={c.op} onChange={(v) => onChange({ ...c, op: (v || "contains") as SignatureCondition["op"] })} options={OPS.map((o) => ({ value: o, label: CONDITION_OP_LABEL[o] }))} />
          ) : null}
        </div>
      </div>
      {c.op !== "exists" || c.type === "path" ? (
        c.type === "version" ? (
          <Input aria-label="Wyrażenie z grupą wersji" disabled={readOnly} className="mono" value={c.extract ?? ""} onChange={(e) => onChange({ ...c, extract: e.target.value })} placeholder="np. Jenkins ([\d.]+)" />
        ) : (
          <Input
            aria-label="Wartość"
            disabled={readOnly}
            className="mono"
            value={c.value ?? ""}
            onChange={(e) => onChange({ ...c, value: e.target.value })}
            placeholder={c.type === "favicon_hash" ? "np. 81586312" : c.type === "path" ? "opcjonalnie: tekst w odpowiedzi" : "wartość do porównania"}
          />
        )
      ) : null}
    </li>
  );
}

function Tester({ sig }: { sig: SignatureInput }) {
  const [mode, setMode] = React.useState<"service" | "raw">("service");
  const [q, setQ] = React.useState("");
  const [serviceId, setServiceId] = React.useState<string | null>(null);
  const [raw, setRaw] = React.useState({ status: "200", headers: "Server: Apache/2.2.15 (CentOS)\nX-Powered-By: PHP/5.4.16\nSet-Cookie: PHPSESSID=abc; path=/", body: "<title>Panel</title>" });
  const [result, setResult] = React.useState<SignatureTestResult | null>(null);
  const [pending, setPending] = React.useState(false);
  const dq = useDebouncedValue(q);
  const services = useQuery({ queryKey: ["services", "tester", dq], queryFn: () => api.services.list({ q: dq, web: "true", page_size: 8 }) });
  const run = async () => {
    setPending(true);
    try {
      const target = mode === "service" ? { service_id: serviceId! } : { raw: { status_code: Number(raw.status) || 200, headers: raw.headers, body: raw.body } };
      setResult(await api.signatures.test({ signature: sig, target }));
    } catch (e) {
      toast.error("Test nie powiódł się", { description: errorMessage(e) });
    } finally {
      setPending(false);
    }
  };
  return (
    <Panel title="Testuj sygnaturę" description="Sprawdź regułę na usłudze z inwentarza lub na wklejonej odpowiedzi HTTP. Test nie wysyła ruchu do sieci.">
      <div className="grid gap-4">
        <Segmented
          aria-label="Źródło testu"
          value={mode}
          onChange={(m) => {
            setMode(m);
            setResult(null);
          }}
          options={[
            { value: "service", label: "Usługa z inwentarza" },
            { value: "raw", label: "Wklejona odpowiedź" },
          ]}
        />
        {mode === "service" ? (
          <div className="grid gap-2">
            <SearchInput value={q} onChange={setQ} placeholder="np. jenkins, phpmyadmin, 10.0.20.8" />
            <ul className="scroll-quiet max-h-56 divide-y divide-line overflow-y-auto rounded-lg border border-line">
              {(services.data?.items ?? []).map((s) => (
                <li key={s.id}>
                  <button type="button" onClick={() => setServiceId(s.id)} aria-pressed={serviceId === s.id} className={cn("grid w-full gap-0.5 px-3 py-2 text-left text-sm hover:bg-surface-2", serviceId === s.id && "bg-accent/10")}>
                    <span className="mono font-semibold">
                      {s.ip}:{s.port}
                    </span>
                    <span className="truncate text-xs text-ink-2">
                      {s.technologies.slice(0, 2).join(", ") || s.product} {s.title ? `— „${s.title}”` : ""}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="grid gap-2">
            <Field label="Kod odpowiedzi" htmlFor="raw-status">
              <Input id="raw-status" className="w-28" value={raw.status} onChange={(e) => setRaw({ ...raw, status: e.target.value })} />
            </Field>
            <Field label="Nagłówki" htmlFor="raw-headers">
              <Textarea id="raw-headers" className="mono text-xs" value={raw.headers} onChange={(e) => setRaw({ ...raw, headers: e.target.value })} />
            </Field>
            <Field label="Treść (HTML)" htmlFor="raw-body">
              <Textarea id="raw-body" className="mono min-h-20 text-xs" value={raw.body} onChange={(e) => setRaw({ ...raw, body: e.target.value })} />
            </Field>
          </div>
        )}
        <Guard permission="signatures:test">
          <Button variant="primary" onClick={run} disabled={pending || (mode === "service" && !serviceId)}>
            {pending ? <Spinner /> : <FlaskConical />} Testuj
          </Button>
        </Guard>
        {result ? (
          <div className="grid gap-3" aria-live="polite">
            <div className={cn("flex items-center gap-2 rounded-lg p-3 font-bold", result.matched ? "bg-success-soft text-success" : "bg-surface-3 text-ink")}>
              {result.matched ? <CircleCheck className="size-5" aria-hidden /> : <CircleX className="size-5" aria-hidden />}
              {result.matched ? `Dopasowano: ${result.target_label}` : `Brak dopasowania: ${result.target_label}`}
            </div>
            <ul className="grid gap-1.5 text-sm">
              {result.conditions.map((c) => (
                <li key={c.index} className="flex items-start gap-2">
                  {c.matched ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-success" aria-label="spełniony" /> : <CircleX className="mt-0.5 size-4 shrink-0 text-ink-3" aria-label="niespełniony" />}
                  <span>
                    Warunek {c.index + 1}: {c.matched ? <code className="mono rounded bg-accent/15 px-1 text-xs">{c.evidence}</code> : <span className="text-ink-2">niespełniony</span>}
                  </span>
                </li>
              ))}
            </ul>
            {result.extracted_version ? <Chip tone="accent">Wykryta wersja: {result.extracted_version}</Chip> : null}
            {!result.safety.ok ? (
              <div className="rounded-lg border border-danger/40 bg-danger-soft p-3 text-sm text-danger">
                {result.safety.issues.map((i) => (
                  <p key={i}>{i}</p>
                ))}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

export function SignatureEditor({ id }: { id: string }) {
  const params = useSearchParams();
  const isNew = id === "new";
  const fromId = params.get("from");
  const existing = useQuery({ queryKey: ["signature", id], queryFn: () => api.signatures.get(id), enabled: !isNew });
  const source = useQuery({ queryKey: ["signature", fromId], queryFn: () => api.signatures.get(fromId!), enabled: isNew && Boolean(fromId) });

  if (existing.isError) return <Container className="py-8"><ErrorState error={existing.error} onRetry={() => existing.refetch()} /></Container>;
  const base = isNew ? (fromId ? source.data : null) : existing.data;
  if ((!isNew && !existing.data) || (isNew && fromId && !source.data))
    return <Container className="grid gap-4 py-8"><Skeleton className="h-10 w-80" /><Skeleton className="h-96" /></Container>;
  const initial: SignatureInput = base
    ? {
        name: isNew ? `${base.name} (kopia)` : base.name,
        description: base.description,
        category: base.category,
        technology: base.technology,
        score_weight: base.score_weight,
        enabled: base.enabled,
        match: base.match,
        tags: base.tags,
      }
    : EMPTY;
  return <EditorBody key={`${id}|${fromId ?? ""}`} id={id} isNew={isNew} existing={existing.data ?? null} initial={initial} />;
}

function EditorBody({ id, isNew, existing: existingData, initial }: { id: string; isNew: boolean; existing: Signature | null; initial: SignatureInput }) {
  const router = useRouter();
  const qc = useQueryClient();
  const can = useCan();
  const existing = { data: existingData ?? undefined };
  const [sig, setSig] = React.useState<SignatureInput>(initial);
  const [saving, setSaving] = React.useState(false);
  const [confirmDelete, setConfirmDelete] = React.useState(false);

  const builtin = existing.data?.source === "builtin";
  const readOnly = builtin || !can(isNew ? "signatures:create" : "signatures:update");
  const issues = localSafety(sig);
  const yaml = YAML.stringify({ signatures: [{ ...sig, technology: sig.technology || undefined }] });
  const setCond = (i: number, c: SignatureCondition) => setSig((s) => ({ ...s, match: { ...s.match, conditions: s.match.conditions.map((x, j) => (j === i ? c : x)) } }));

  const save = async () => {
    setSaving(true);
    try {
      const r = isNew ? await api.signatures.create(sig) : await api.signatures.update(id, sig);
      qc.invalidateQueries({ queryKey: ["signatures"] });
      qc.setQueryData(["signature", r.id], r);
      toast.success(isNew ? "Utworzono sygnaturę" : "Zapisano sygnaturę", { description: `Dopasowania w ostatnim skanie: ${r.matches_last_scan}` });
      if (isNew) router.replace(`/signatures/${r.id}`);
    } catch (e) {
      toast.error("Nie udało się zapisać sygnatury", { description: errorMessage(e) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Container className="pb-12">
      <PageHeader
        back={{ href: "/signatures", label: "Sygnatury" }}
        title={isNew ? "Nowa sygnatura" : sig.name || existing.data?.name}
        description={
          isNew
            ? "Opisz cechę, którą skaner ma rozpoznać. Reguła jest sprawdzana pod kątem bezpieczeństwa przed zapisem."
            : `${builtin ? "Sygnatura wbudowana" : `Sygnatura własna, autor: ${existing.data?.author}`}. Wersja ${existing.data?.version}, zmieniona ${fmtRelative(existing.data?.updated_at)}.`
        }
        meta={!isNew ? <Chip tone="outline">Dopasowania w ostatnim skanie: {existing.data?.matches_last_scan}</Chip> : null}
        actions={
          <>
            {!isNew ? (
              <Guard permission="signatures:create">
                <Button onClick={() => router.push(`/signatures/new?from=${id}`)}>
                  <Copy /> Utwórz kopię
                </Button>
              </Guard>
            ) : null}
            {!isNew && !builtin ? (
              <Guard permission="signatures:delete">
                <Button variant="danger" onClick={() => setConfirmDelete(true)}>
                  <Trash2 /> Usuń
                </Button>
              </Guard>
            ) : null}
            {!builtin ? (
              <Guard permission={isNew ? "signatures:create" : "signatures:update"}>
                <Button variant="primary" onClick={save} disabled={saving || issues.length > 0}>
                  {saving ? <Spinner /> : <Save />} {isNew ? "Utwórz sygnaturę" : "Zapisz zmiany"}
                </Button>
              </Guard>
            ) : null}
          </>
        }
      />
      {builtin ? (
        <p className="mb-6 rounded-xl border border-line bg-surface-2 px-4 py-3 text-sm">
          Sygnatury wbudowane można tylko włączać i wyłączać na liście. Aby zmienić warunki, utwórz kopię jako sygnaturę własną.
        </p>
      ) : null}
      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <div className="grid gap-6">
          <Panel title="Opis">
            <div className="grid gap-4">
              <Field label="Nazwa" htmlFor="sig-name">
                <Input id="sig-name" disabled={readOnly} value={sig.name} onChange={(e) => setSig({ ...sig, name: e.target.value })} placeholder="np. Panel administracyjny Grafany" />
              </Field>
              <Field label="Opis" htmlFor="sig-desc">
                <Textarea id="sig-desc" disabled={readOnly} value={sig.description} onChange={(e) => setSig({ ...sig, description: e.target.value })} className="min-h-16" />
              </Field>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Kategoria">
                  <SimpleSelect aria-label="Kategoria" disabled={readOnly} value={sig.category} onChange={(v) => setSig({ ...sig, category: (v || "technology") as Signature["category"] })} options={CATEGORIES.map((c) => ({ value: c, label: categoryLabel(c) }))} />
                </Field>
                <Field label="Rozpoznawana technologia" htmlFor="sig-tech">
                  <Input id="sig-tech" disabled={readOnly} value={sig.technology ?? ""} onChange={(e) => setSig({ ...sig, technology: e.target.value || null })} placeholder="np. Grafana" />
                </Field>
              </div>
              <Field label={`Wpływ na priorytet: +${sig.score_weight} pkt`} hint="Ile punktów doda dopasowanie do priorytetu analitycznego znaleziska.">
                <Slider aria-label="Wpływ na priorytet" disabled={readOnly} min={0} max={50} step={5} value={[sig.score_weight]} onValueChange={([v]) => setSig({ ...sig, score_weight: v })} />
              </Field>
              <Field label="Tagi" htmlFor="sig-tags">
                <TagInput id="sig-tags" value={sig.tags} onChange={(tags) => setSig({ ...sig, tags })} />
              </Field>
              <label className="flex items-center justify-between gap-3 rounded-lg border border-line p-3 text-sm font-semibold">
                Sygnatura aktywna
                <Switch disabled={readOnly} checked={sig.enabled} onCheckedChange={(enabled) => setSig({ ...sig, enabled })} />
              </label>
            </div>
          </Panel>
          <Panel
            title="Warunki dopasowania"
            actions={
              <Segmented
                aria-label="Łączenie warunków"
                size="sm"
                value={sig.match.operator}
                onChange={(operator) => !readOnly && setSig({ ...sig, match: { ...sig.match, operator } })}
                options={[
                  { value: "and", label: "Wszystkie (AND)" },
                  { value: "or", label: "Dowolny (OR)" },
                ]}
              />
            }
          >
            <div className="grid gap-3">
              <ul className="grid gap-3">
                {sig.match.conditions.map((c, i) => (
                  <ConditionRow
                    key={i}
                    c={c}
                    index={i}
                    readOnly={readOnly}
                    onChange={(nc) => setCond(i, nc)}
                    onRemove={() => setSig({ ...sig, match: { ...sig.match, conditions: sig.match.conditions.filter((_, j) => j !== i) } })}
                  />
                ))}
              </ul>
              {!readOnly ? (
                <Button
                  variant="secondary"
                  className="justify-self-start"
                  disabled={sig.match.conditions.length >= 10}
                  onClick={() => setSig({ ...sig, match: { ...sig.match, conditions: [...sig.match.conditions, { type: "html", op: "contains", value: "" }] } })}
                >
                  <Plus /> Dodaj warunek
                </Button>
              ) : null}
              <div className={cn("grid gap-1.5 rounded-lg p-3 text-sm", issues.length ? "bg-danger-soft text-danger" : "bg-success-soft text-success")} aria-live="polite">
                <span className="flex items-center gap-2 font-bold">
                  {issues.length ? <ShieldAlert className="size-4" aria-hidden /> : <ShieldCheck className="size-4" aria-hidden />}
                  {issues.length ? "Reguła wymaga poprawek" : "Reguła jest bezpieczna: tylko pasywne sprawdzenia GET/HEAD"}
                </span>
                {issues.map((i) => (
                  <span key={i}>{i}</span>
                ))}
              </div>
            </div>
          </Panel>
        </div>
        <div className="grid gap-6">
          <Tester sig={sig} />
          <Panel title="Podgląd YAML" description="Format importu i eksportu sygnatur.">
            <pre className="mono scroll-quiet max-h-96 overflow-auto rounded-lg bg-chrome p-4 text-xs leading-relaxed text-chrome-ink">{yaml}</pre>
          </Panel>
        </div>
      </div>
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Usunąć sygnaturę?"
        description="Reguła przestanie działać od następnego skanu. Wcześniejsze znaleziska pozostaną. Tej operacji nie można cofnąć."
        confirmLabel="Usuń sygnaturę"
        onConfirm={async () => {
          try {
            await api.signatures.remove(id);
            qc.invalidateQueries({ queryKey: ["signatures"] });
            toast.success("Usunięto sygnaturę");
            router.push("/signatures");
          } catch (e) {
            toast.error("Nie udało się usunąć", { description: errorMessage(e) });
          }
        }}
      />
    </Container>
  );
}
