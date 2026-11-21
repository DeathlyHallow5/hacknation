"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, CircleX, PlugZap, Save, TriangleAlert } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard } from "@/components/data/bits";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Segmented, Slider, SwitchRow } from "@/components/ui/form-controls";
import { Chip, DefinitionList, Panel, Skeleton, Spinner } from "@/components/ui/misc";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { DefectDojoConfig } from "@/lib/api/types";
import { fmtRelative, fmtSmart } from "@/lib/format";
import { useCan } from "@/lib/session";

/** "All good" is quiet: a check and plain text. Only a failure is a red chip. */
function OkText({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm whitespace-nowrap text-ink">
      <Check className="size-4 shrink-0 text-ink-2" strokeWidth={2.5} aria-hidden />
      {children}
    </span>
  );
}

function DefectDojoPanel() {
  const q = useQuery({ queryKey: ["defectdojo"], queryFn: api.integrations.defectdojo });
  const d = q.data;
  return (
    <Panel
      title="DefectDojo"
      description={
        <>
          Findingi informacyjne (severity: Info) albo evidence do analizy. API: <code className="mono">/api/v2</code>
        </>
      }
      actions={
        d?.last_test ? (
          d.last_test.ok ? (
            <OkText>
              Połączono (v{d.last_test.version}, {d.last_test.latency_ms} ms)
            </OkText>
          ) : (
            <Chip tone="danger">
              <CircleX className="size-3.5" aria-hidden /> Błąd połączenia
            </Chip>
          )
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
    <div className="grid gap-8 lg:grid-cols-2">
      <div className="grid content-start gap-4">
        <Field label="Adres instancji" htmlFor="dd-url">
          <Input id="dd-url" value={url} disabled={!editable} onChange={(e) => setUrl(e.target.value)} />
        </Field>
        <Field
          label="Token API"
          htmlFor="dd-token"
          hint={d.api_token_set ? `Zapisany token: ${d.api_token_masked}. Token jest przechowywany w postaci zaszyfrowanej i nigdy nie jest pokazywany w całości.` : "Brak tokenu."}
        >
          <Input id="dd-token" type="password" autoComplete="off" value={token} disabled={!editable} onChange={(e) => setToken(e.target.value)} placeholder={d.api_token_set ? "Wpisz, aby zastąpić" : "Token z DefectDojo, klucz API v2"} />
        </Field>
        {/* Product and engagement come from DefectDojo and cannot be edited here: shown as data, not as greyed-out fields. */}
        <DefinitionList
          items={[
            { label: "Produkt", value: <>{d.product_name} <span className="tabular text-ink-2">(#{d.product_id})</span></> },
            { label: "Engagement", value: <>{d.engagement_name} <span className="tabular text-ink-2">(#{d.engagement_id})</span></> },
          ]}
        />
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
        <SwitchRow
          label="Wysyłaj automatycznie po każdym skanie"
          description={`Nowe znaleziska z priorytetem co najmniej ${minScore}.`}
          checked={auto}
          disabled={!editable}
          onCheckedChange={setAuto}
          className="border-t border-line pt-4"
        />
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
      <div className="grid content-start gap-1">
        <h3 className="text-sm font-semibold">Historia wysyłek</h3>
        <ul className="divide-y divide-line">
          {(exports.data ?? []).map((e) => (
            <li key={e.id} className="grid gap-0.5 py-3 text-sm">
              <span className="flex flex-wrap items-center justify-between gap-2">
                <span className="tabular font-semibold">
                  {e.count} × {e.as === "finding" ? "finding" : "evidence"}
                </span>
                {e.status === "success" ? (
                  <OkText>Wysłano</OkText>
                ) : e.status === "partial" ? (
                  <Chip tone="warning">
                    <TriangleAlert className="size-3" aria-hidden /> Częściowo
                  </Chip>
                ) : (
                  <Chip tone="danger">
                    <CircleX className="size-3" aria-hidden /> Błąd
                  </Chip>
                )}
              </span>
              <span className="text-pretty text-ink-2">{e.message}</span>
              <span className="text-xs text-ink-2">
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
      <PageHeader title="Integracje" />
      <div className="grid gap-6">
        <DefectDojoPanel />
        <Panel title="Silniki skanujące" description="Wersje narzędzi, których używa skaner." flush>
          <ul className="divide-y divide-line">
            {(engines.data ?? []).map((e) => (
              <li key={e.name} className="grid gap-x-6 gap-y-1 px-5 py-3 sm:grid-cols-[10rem_minmax(0,1fr)_auto] sm:items-center">
                <span className="grid gap-0.5">
                  <span className="mono font-medium">{e.name}</span>
                  <span className="text-xs text-ink-2">{e.version ? `wersja ${e.version}` : "nie znaleziono"}</span>
                </span>
                <span className="text-sm text-pretty text-ink-2">
                  {e.purpose}
                  {e.last_used_at ? `; użyty ${fmtRelative(e.last_used_at)}` : null}
                </span>
                {e.status === "ok" ? (
                  <OkText>Gotowy</OkText>
                ) : (
                  <Chip tone="danger">
                    <CircleX className="size-3" aria-hidden /> Problem
                  </Chip>
                )}
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title="Źródła pasywne" description="Certificate Transparency, DNS, eksporty z CMDB: dane bez aktywnego skanowania.">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="grid gap-0.5">
              <p className="text-sm font-semibold">Brak skonfigurowanych źródeł.</p>
              <p className="max-w-[65ch] text-sm text-pretty text-ink-2">Gdy laboratorium udostępni dane pasywne, trafią do tego samego modelu co wyniki skanera, z oznaczeniem źródła.</p>
            </div>
            <Button disabled>Dodaj źródło</Button>
          </div>
        </Panel>
      </div>
    </Container>
  );
}
