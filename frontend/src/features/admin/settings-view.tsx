"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Lock, Save } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard, TagInput } from "@/components/data/bits";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Slider, Textarea } from "@/components/ui/form-controls";
import { DefinitionList, Panel, Skeleton } from "@/components/ui/misc";
import { ConfirmDialog } from "@/components/ui/overlays";
import { ApiError, errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Settings } from "@/lib/api/types";
import { fmtDate, fmtNumber, fmtPercent, fmtRelative, plural } from "@/lib/format";
import { parseCidr } from "@/lib/net";
import { useCan } from "@/lib/session";

function EncryptionPanel() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["encryption"], queryFn: api.settings.encryption });
  const [confirm, setConfirm] = React.useState(false);
  const e = q.data;
  return (
    <Panel
      title="Szyfrowanie danych w spoczynku"
      description="Klucz pochodzi z menedżera sekretów, nie z repozytorium."
      actions={
        e ? (
          <span className="inline-flex items-center gap-1.5 text-sm text-ink">
            <Lock className="size-4 text-ink-2" aria-hidden /> Włączone
          </span>
        ) : null
      }
    >
      {!e ? (
        <Skeleton className="h-40" />
      ) : (
        <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
          <div className="grid content-start gap-4 text-sm">
            <DefinitionList
              items={[
                { label: "Algorytm", value: e.algorithm },
                { label: "Dostawca klucza", value: e.provider },
                { label: "Identyfikator klucza", value: <span className="mono">{e.key_id}</span> },
                { label: "Ostatnia rotacja", value: fmtDate(e.rotated_at) },
                { label: "Ostatnia weryfikacja", value: fmtRelative(e.last_check_at) },
              ]}
            />
            <Guard permission="settings:manage">
              <Button className="justify-self-start" onClick={() => setConfirm(true)}>
                <KeyRound /> Wykonaj rotację klucza
              </Button>
            </Guard>
          </div>
          {/* The list of encrypted columns sits in the panel as a plain table, without a second frame. */}
          <table className="w-full self-start text-sm">
            <caption className="sr-only">Szyfrowane kolumny</caption>
            <thead className="border-b border-line text-left text-xs text-ink-2">
              <tr>
                <th className="py-2 pr-3 font-semibold">Tabela i kolumna</th>
                <th className="py-2 font-semibold">Zawartość</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {e.encrypted_fields.map((f) => (
                <tr key={`${f.table}.${f.column}`}>
                  <td className="mono py-1.5 pr-3 align-top text-sm [overflow-wrap:anywhere]">
                    {f.table}.{f.column}
                  </td>
                  <td className="py-1.5 align-top text-pretty">{f.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        destructive={false}
        title="Wykonać rotację klucza?"
        description="Dane zostaną ponownie zaszyfrowane nowym kluczem. Operacja jest bezpieczna i zostanie zapisana w dzienniku zdarzeń."
        confirmLabel="Wykonaj rotację"
        onConfirm={async () => {
          setConfirm(false);
          try {
            const r = await api.settings.rotateKey();
            qc.setQueryData(["encryption"], r);
            toast.success("Wykonano rotację klucza", { description: r.key_id });
          } catch (err) {
            toast.error("Rotacja nie powiodła się", { description: errorMessage(err) });
          }
        }}
      />
    </Panel>
  );
}

export function SettingsView() {
  const q = useQuery({ queryKey: ["settings"], queryFn: api.settings.get });
  if (q.isError) return <Container className="py-8"><ErrorState error={q.error} onRetry={() => q.refetch()} /></Container>;
  if (!q.data) return <Container className="py-8"><Skeleton className="h-96" /></Container>;
  return <SettingsForm key={JSON.stringify(q.data)} data={q.data} />;
}

/** Keyed by the saved settings, so it re-initialises after each save. */
function SettingsForm({ data }: { data: Settings }) {
  const qc = useQueryClient();
  const can = useCan();
  const q = { data };
  const [s, setS] = React.useState<Settings | null>(() => structuredClone(data));
  const [errors, setErrors] = React.useState<Record<string, string>>({});
  const editable = can("settings:manage");
  const dirty = s && q.data && JSON.stringify(s) !== JSON.stringify(q.data);
  const badCidrs = s?.scan_safety.excluded_cidrs.filter((c) => !parseCidr(c)) ?? [];

  const save = async () => {
    if (!s) return;
    try {
      const r = await api.settings.update(s);
      qc.setQueryData(["settings"], r);
      setErrors({});
      toast.success("Zapisano ustawienia", { description: "Obowiązują od następnego skanowania." });
    } catch (e) {
      if (e instanceof ApiError && e.fields) setErrors(e.fields);
      toast.error("Nie udało się zapisać", { description: errorMessage(e) });
    }
  };

  return (
    <Container className="pb-12">
      <PageHeader
        title="Ustawienia"
        description="Granice i tempo skanowania oraz szyfrowanie danych. Każda zmiana ustawień trafia do dziennika zdarzeń."
        actions={
          <Guard permission="settings:manage">
            <Button variant="primary" onClick={save} disabled={!dirty || badCidrs.length > 0}>
              <Save /> Zapisz ustawienia
            </Button>
          </Guard>
        }
      />
      {!s ? (
        <Skeleton className="h-96" />
      ) : (
        <div className="grid gap-6">
          <div className="grid items-start gap-6 xl:grid-cols-2">
            <Panel title="Bezpieczeństwo skanowania" description="Żaden profil nie może przekroczyć tych limitów.">
              <div className="grid gap-5">
                <Field label={`Maksymalne tempo: ${fmtNumber(s.scan_safety.max_rate_rps)} zapytań/s`} error={errors.max_rate_rps}>
                  <Slider aria-label="Maksymalne tempo" disabled={!editable} min={50} max={2000} step={50} value={[s.scan_safety.max_rate_rps]} onValueChange={([v]) => setS({ ...s, scan_safety: { ...s.scan_safety, max_rate_rps: v } })} />
                </Field>
                <Field label={`Równoległe połączenia: ${s.scan_safety.max_concurrency}`} error={errors.max_concurrency}>
                  <Slider aria-label="Równoległe połączenia" disabled={!editable} min={1} max={256} step={1} value={[s.scan_safety.max_concurrency]} onValueChange={([v]) => setS({ ...s, scan_safety: { ...s.scan_safety, max_concurrency: v } })} />
                </Field>
                <Field label={`Żądania HTTP na host w jednym przebiegu: ${s.scan_safety.max_http_requests_per_host}`}>
                  <Slider aria-label="Żądania HTTP na host" disabled={!editable} min={1} max={50} step={1} value={[s.scan_safety.max_http_requests_per_host]} onValueChange={([v]) => setS({ ...s, scan_safety: { ...s.scan_safety, max_http_requests_per_host: v } })} />
                </Field>
                <Field label="Porty dozwolone do testów" htmlFor="ports" hint="Lista z wytycznych laboratorium; używana przez profil „Porty dozwolone”.">
                  <Textarea id="ports" disabled={!editable} className="mono min-h-20 text-sm" value={s.scan_safety.allowed_ports} onChange={(e) => setS({ ...s, scan_safety: { ...s.scan_safety, allowed_ports: e.target.value } })} />
                </Field>
                <Field label="Zakresy wykluczone (nigdy nie skanowane)" error={badCidrs.length ? `Niepoprawne zakresy: ${badCidrs.join(", ")}` : errors.excluded_cidrs}>
                  <TagInput mono value={s.scan_safety.excluded_cidrs} onChange={(v) => setS({ ...s, scan_safety: { ...s.scan_safety, excluded_cidrs: v.map((x) => x.replace(/^#/, "")) } })} placeholder="np. 10.0.250.0/24 i Enter" />
                </Field>
                <Field label="Identyfikacja skanera (User-Agent)" htmlFor="ua" hint="Administratorzy sieci od razu wiedzą, kto skanuje i gdzie zgłosić uwagi.">
                  <Input id="ua" disabled={!editable} className="mono text-sm" value={s.scan_safety.user_agent} onChange={(e) => setS({ ...s, scan_safety: { ...s.scan_safety, user_agent: e.target.value } })} />
                </Field>
              </div>
            </Panel>
            <div className="grid gap-6">
              <Panel title="Wykrywanie zmian">
                <div className="grid gap-5">
                  <Field
                    label={`Host nieaktywny po ${s.change_detection.inactive_after_misses} ${plural(s.change_detection.inactive_after_misses, ["skanie", "kolejnych skanach", "kolejnych skanach"])} bez odpowiedzi`}
                    error={errors.inactive_after_misses}
                  >
                    <Slider aria-label="Liczba skanów bez odpowiedzi" disabled={!editable} min={1} max={10} step={1} value={[s.change_detection.inactive_after_misses]} onValueChange={([v]) => setS({ ...s, change_detection: { ...s.change_detection, inactive_after_misses: v } })} />
                  </Field>
                  <Field label={`Powtórne pomiary hostów niestabilnych: ${s.change_detection.unstable_retries}`}>
                    <Slider aria-label="Powtórne pomiary" disabled={!editable} min={0} max={5} step={1} value={[s.change_detection.unstable_retries]} onValueChange={([v]) => setS({ ...s, change_detection: { ...s.change_detection, unstable_retries: v } })} />
                  </Field>
                  <Field label={`Próg pewności zmiany: ${fmtPercent(s.change_detection.change_confidence_threshold)}`} hint="Zmiany poniżej progu są oznaczane jako możliwy szum.">
                    <Slider aria-label="Próg pewności" disabled={!editable} min={0.3} max={0.95} step={0.05} value={[s.change_detection.change_confidence_threshold]} onValueChange={([v]) => setS({ ...s, change_detection: { ...s.change_detection, change_confidence_threshold: Math.round(v * 100) / 100 } })} />
                  </Field>
                  <Field label={`Pomiary kontrolne w dzień co ${s.change_detection.recheck_interval_minutes} min`}>
                    <Slider aria-label="Interwał pomiarów kontrolnych" disabled={!editable} min={30} max={480} step={30} value={[s.change_detection.recheck_interval_minutes]} onValueChange={([v]) => setS({ ...s, change_detection: { ...s.change_detection, recheck_interval_minutes: v } })} />
                  </Field>
                </div>
              </Panel>
              <Panel title="Przechowywanie i domyślne okno">
                <div className="grid gap-4 sm:grid-cols-2">
                  <Field label="Wyniki skanów (dni)" htmlFor="ret-scans">
                    <Input id="ret-scans" type="number" disabled={!editable} value={s.retention.scans_days} onChange={(e) => setS({ ...s, retention: { ...s.retention, scans_days: Number(e.target.value) } })} />
                  </Field>
                  <Field label="Dziennik zdarzeń (dni)" htmlFor="ret-audit">
                    <Input id="ret-audit" type="number" disabled={!editable} value={s.retention.audit_days} onChange={(e) => setS({ ...s, retention: { ...s.retention, audit_days: Number(e.target.value) } })} />
                  </Field>
                  <Field label="Początek domyślnego okna" htmlFor="dw-start">
                    <Input id="dw-start" type="time" disabled={!editable} value={s.default_window.start} onChange={(e) => setS({ ...s, default_window: { ...s.default_window, start: e.target.value } })} />
                  </Field>
                  <Field label="Koniec domyślnego okna" htmlFor="dw-end">
                    <Input id="dw-end" type="time" disabled={!editable} value={s.default_window.end} onChange={(e) => setS({ ...s, default_window: { ...s.default_window, end: e.target.value } })} />
                  </Field>
                </div>
              </Panel>
            </div>
          </div>
          <EncryptionPanel />
        </div>
      )}
    </Container>
  );
}
