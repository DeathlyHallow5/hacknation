"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { CircleCheck, CircleX, Cpu, PlugZap, Save, Unplug } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard } from "@/components/data/bits";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Segmented, Slider, Switch } from "@/components/ui/form-controls";
import { Chip, Panel, Skeleton, Spinner } from "@/components/ui/misc";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { DefectDojoConfig } from "@/lib/api/types";
import { fmtRelative, fmtSmart } from "@/lib/format";
import { useCan } from "@/lib/session";

function DefectDojoPanel() {
  const q = useQuery({ queryKey: ["defectdojo"], queryFn: api.integrations.defectdojo });
  const d = q.data;
  return (
    <Panel
      title="DefectDojo"
      description="Wysyłka wybranych obserwacji jako findingów informacyjnych (severity: Info) lub jako evidence do dalszej analizy. API: /api/v2."
      actions={
        d?.last_test ? (
          <Chip tone={d.last_test.ok ? "success" : "danger"}>
            {d.last_test.ok ? <CircleCheck className="size-3.5" aria-hidden /> : <CircleX className="size-3.5" aria-hidden />}
            {d.last_test.ok ? `Połączono (v${d.last_test.version}, ${d.last_test.latency_ms} ms)` : "Błąd połączenia"}
          </Chip>
        ) : null
      }
    >
      {q.isError ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : null}
      {!d ? <Skeleton className="h-64" /> : <DefectDojoForm key={[d.url, d.auto_export, d.min_score, d.export_as].join("|")} d={d} />}
    </Panel>
  );
}

/** Keyed by the saved values, so it re-initialises after every save. */
function DefectDojoForm({ d }: { d: DefectDojoConfig }) {
  const qc = useQueryClient();
  const can = useCan();
  const exports = useQuery({ queryKey: ["defectdojo-exports"], queryFn: api.integrations.exports });
  const [url, setUrl] = React.useState(d.url);
  const [token, setToken] = React.useState("");
  const [auto, setAuto] = React.useState(d.auto_export);
  const [minScore, setMinScore] = React.useState(d.min_score);
  const [as, setAs] = React.useState<"finding" | "evidence">(d.export_as);
  const [testing, setTesting] = React.useState(false);
  const editable = can("integrations:manage");

  const save = async () => {
    try {
      const r = await api.integrations.saveDefectdojo({ url, auto_export: auto, min_score: minScore, export_as: as, ...(token ? { api_token: token } : {}) });
      setToken("");
      qc.setQueryData(["defectdojo"], r);
      toast.success("Zapisano konfigurację DefectDojo", { description: token ? "Nowy token zapisano w postaci zaszyfrowanej." : undefined });
    } catch (e) {
      toast.error("Nie udało się zapisać", { description: errorMessage(e) });
    }
  };
  const test = async () => {
    setTesting(true);
    try {
      const r = await api.integrations.testDefectdojo();
      qc.setQueryData(["defectdojo"], r);
      if (r.last_test?.ok) toast.success("Połączenie działa", { description: r.last_test.message });
      else toast.error("Brak połączenia", { description: r.last_test?.message });
    } catch (e) {
      toast.error("Test nie powiódł się", { description: errorMessage(e) });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="grid content-start gap-4">
        <Field label="Adres instancji" htmlFor="dd-url">
          <Input id="dd-url" value={url} disabled={!editable} onChange={(e) => setUrl(e.target.value)} />
        </Field>
        <Field
          label="Token API"
          htmlFor="dd-token"
          hint={d.api_token_set ? `Zapisany token: ${d.api_token_masked}. Token jest przechowywany w postaci zaszyfrowanej i nigdy nie jest pokazywany w całości.` : "Brak tokenu."}
        >
          <Input id="dd-token" type="password" autoComplete="off" value={token} disabled={!editable} onChange={(e) => setToken(e.target.value)} placeholder={d.api_token_set ? "Wpisz, aby zastąpić" : "Token z DefectDojo → API v2 Key"} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Produkt">
            <Input value={`${d.product_name} (#${d.product_id})`} disabled />
          </Field>
          <Field label="Engagement">
            <Input value={`${d.engagement_name} (#${d.engagement_id})`} disabled />
          </Field>
        </div>
        <Field label="Domyślny sposób wysyłki">
          <Segmented
            aria-label="Sposób wysyłki"
            value={as}
            onChange={(v) => editable && setAs(v)}
            options={[
              { value: "finding", label: "Finding informacyjny" },
              { value: "evidence", label: "Evidence" },
            ]}
          />
        </Field>
        <label className="flex items-start justify-between gap-4 rounded-lg border border-line p-3">
          <span className="grid gap-0.5">
            <span className="text-sm font-semibold">Wysyłaj automatycznie po każdym skanie</span>
            <span className="text-sm text-ink-2">Nowe znaleziska z priorytetem co najmniej {minScore}.</span>
          </span>
          <Switch checked={auto} disabled={!editable} onCheckedChange={setAuto} />
        </label>
        {auto ? (
          <Field label={`Minimalny priorytet: ${minScore}`}>
            <Slider aria-label="Minimalny priorytet" min={0} max={100} step={5} value={[minScore]} disabled={!editable} onValueChange={([v]) => setMinScore(v)} />
          </Field>
        ) : null}
        <div className="flex flex-wrap gap-2">
          <Guard permission="integrations:manage">
            <Button variant="primary" onClick={save}>
              <Save /> Zapisz konfigurację
            </Button>
          </Guard>
          <Guard permission="integrations:manage">
            <Button onClick={test} disabled={testing}>
              {testing ? <Spinner /> : <PlugZap />} Testuj połączenie
            </Button>
          </Guard>
        </div>
      </div>
      <div className="grid content-start gap-3">
        <h3 className="text-sm font-bold">Historia wysyłek</h3>
        <ul className="grid gap-2">
          {(exports.data ?? []).map((e) => (
            <li key={e.id} className="grid gap-0.5 rounded-lg border border-line p-3 text-sm">
              <span className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold">
                  {e.count} × {e.as === "finding" ? "finding" : "evidence"}
                </span>
                <Chip tone={e.status === "success" ? "success" : e.status === "partial" ? "warning" : "danger"}>
                  {e.status === "success" ? "Sukces" : e.status === "partial" ? "Częściowo" : "Błąd"}
                </Chip>
              </span>
              <span className="text-sm text-ink-2">{e.message}</span>
              <span className="text-xs text-ink-3">
                {e.by}, {fmtSmart(e.at)}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function IntegrationsView() {
  const engines = useQuery({ queryKey: ["engines"], queryFn: api.integrations.engines });
  return (
    <Container className="pb-12">
      <PageHeader title="Integracje" description="Połączenie z platformą zarządzania podatnościami i stan narzędzi skanujących." />
      <div className="grid gap-6">
        <DefectDojoPanel />
        <Panel title="Silniki skanujące" description="Rdzeń w Rust uruchamia sprawdzone narzędzia open source i normalizuje ich wyniki do jednego modelu danych." flush>
          <ul className="divide-y divide-line">
            {(engines.data ?? []).map((e) => (
              <li key={e.name} className="flex flex-wrap items-center gap-4 px-5 py-3">
                <Cpu className="size-5 text-ink-3" aria-hidden />
                <span className="grid min-w-40 gap-0.5">
                  <span className="mono font-bold">{e.name}</span>
                  <span className="text-xs text-ink-2">{e.version ? `wersja ${e.version}` : "nie znaleziono"}</span>
                </span>
                <span className="flex-1 text-sm text-ink-2">{e.purpose}</span>
                <span className="text-xs text-ink-2">{e.last_used_at ? `użyty ${fmtRelative(e.last_used_at)}` : ""}</span>
                <Chip tone={e.status === "ok" ? "success" : "danger"}>{e.status === "ok" ? "Gotowy" : "Problem"}</Chip>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Źródła pasywne" description="Dane bez aktywnego skanowania (np. certyfikaty z Certificate Transparency, rekordy DNS, eksporty z CMDB).">
          <div className="flex flex-wrap items-center gap-4 rounded-xl border border-dashed border-line-strong p-5">
            <Unplug className="size-6 text-ink-3" aria-hidden />
            <div className="grid flex-1 gap-0.5">
              <span className="font-semibold">Brak skonfigurowanych źródeł</span>
              <span className="text-sm text-ink-2">Gdy laboratorium udostępni dane pasywne, trafią do tego samego modelu co wyniki skanera — z oznaczeniem źródła.</span>
            </div>
            <Button disabled>Dodaj źródło</Button>
          </div>
        </Panel>
      </div>
    </Container>
  );
}
