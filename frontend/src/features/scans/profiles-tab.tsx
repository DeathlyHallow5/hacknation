"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Gauge, Pencil, Plus, Trash2 } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { Guard } from "@/components/data/bits";
import { Button } from "@/components/ui/button";
import { Field, Input, Segmented, Slider, Switch, Textarea } from "@/components/ui/form-controls";
import { Chip, Skeleton } from "@/components/ui/misc";
import { ConfirmDialog, Sheet, SheetBody, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/overlays";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { ScanProfile, ScanProfileInput } from "@/lib/api/types";
import { countLabel, fmtNumber } from "@/lib/format";
import { useCan } from "@/lib/session";

type Mode = { kind: "edit"; profile: ScanProfile } | { kind: "copy"; profile: ScanProfile };

function portsLabel(p: ScanProfile["ports"]) {
  return p.preset === "top100" ? "100 portów" : p.preset === "top1000" ? "1000 portów" : p.preset === "allowed" ? "porty dozwolone" : "porty własne";
}

/** Edit a profile or create a new one from a copy. Inside SheetContent: fresh state on each opening. */
function ProfileForm({ mode, onClose }: { mode: Mode; onClose: () => void }) {
  const qc = useQueryClient();
  const can = useCan();
  const settings = useQuery({ queryKey: ["settings"], queryFn: api.settings.get });
  const src = mode.profile;
  const isNew = mode.kind === "copy";
  const [name, setName] = React.useState(isNew ? `${src.name} (kopia)` : src.name);
  const [description, setDescription] = React.useState(src.description);
  const [preset, setPreset] = React.useState<ScanProfile["ports"]["preset"]>(src.ports.preset);
  const [custom, setCustom] = React.useState(src.ports.custom);
  const [rate, setRate] = React.useState(src.rate_limit_rps);
  const [conc, setConc] = React.useState(src.max_concurrency);
  const [timing, setTiming] = React.useState<ScanProfile["nmap_timing"]>(src.nmap_timing);
  const [retries, setRetries] = React.useState(src.unstable_retries);
  const [http, setHttp] = React.useState(src.http_probe);
  const [tls, setTls] = React.useState(src.tls_probe);
  const [sigs, setSigs] = React.useState<ScanProfile["signatures"]>(src.signatures === "selected" ? "all" : src.signatures);
  const [saving, setSaving] = React.useState(false);
  const [confirmDelete, setConfirmDelete] = React.useState(false);
  const max = settings.data?.scan_safety.max_rate_rps ?? 500;
  const editable = isNew ? can("scans:create") : can("scans:update");
  const portsOk = preset !== "custom" || /^\s*\d+(-\d+)?(\s*,\s*\d+(-\d+)?)*\s*$/.test(custom);

  const save = async () => {
    setSaving(true);
    const body: ScanProfileInput = {
      name: name.trim(),
      description,
      ports: { preset, custom: preset === "custom" ? custom.replace(/\s+/g, "") : "" },
      rate_limit_rps: Math.min(rate, max),
      max_concurrency: conc,
      nmap_timing: timing,
      host_timeout_s: src.host_timeout_s,
      http_probe: http,
      tls_probe: tls,
      follow_redirects: src.follow_redirects,
      max_redirects: src.max_redirects,
      signatures: src.signatures === "selected" && sigs === "all" && !isNew ? "selected" : sigs,
      signature_ids: src.signature_ids,
      unstable_retries: retries,
      batch_strategy: src.batch_strategy,
      batch_prefix: src.batch_prefix,
    };
    try {
      if (isNew) await api.profiles.create(body);
      else await api.profiles.update(src.id, body);
      qc.invalidateQueries({ queryKey: ["profiles"] });
      toast.success(isNew ? "Utworzono profil" : "Zapisano profil", { description: body.name });
      onClose();
    } catch (e) {
      toast.error("Nie udało się zapisać profilu", { description: errorMessage(e) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <SheetHeader>
        <SheetTitle>{isNew ? "Nowy profil skanowania" : src.name}</SheetTitle>
        <SheetDescription>{isNew ? `Na podstawie profilu „${src.name}”.` : src.description}</SheetDescription>
      </SheetHeader>
      <SheetBody className="grid content-start gap-6">
        <Field label="Nazwa" htmlFor="pr-name">
          <Input id="pr-name" disabled={!editable || (!isNew && src.builtin)} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Opis" htmlFor="pr-desc">
          <Textarea id="pr-desc" disabled={!editable} className="min-h-16" value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Field label="Porty">
          <Segmented
            aria-label="Zakres portów"
            value={preset}
            onChange={(v) => editable && setPreset(v)}
            options={[
              { value: "top100", label: "100 najczęstszych" },
              { value: "top1000", label: "1000 najczęstszych" },
              { value: "allowed", label: "Dozwolone" },
              { value: "custom", label: "Własne" },
            ]}
          />
        </Field>
        {preset === "custom" ? (
          <Field label="Lista portów" htmlFor="pr-ports" hint="Porty i zakresy oddzielone przecinkami, np. 22,80,443,8000-8099." error={portsOk ? null : "Niepoprawny format listy portów."}>
            <Input id="pr-ports" className="mono" disabled={!editable} value={custom} onChange={(e) => setCustom(e.target.value)} aria-invalid={!portsOk} />
          </Field>
        ) : null}
        <Field label={`Limit tempa: ${fmtNumber(Math.min(rate, max))} zapytań/s`} hint={`Globalny limit bezpieczeństwa: ${fmtNumber(max)} zapytań/s (Administracja → Ustawienia).`}>
          <Slider aria-label="Limit zapytań na sekundę" disabled={!editable} min={10} max={max} step={10} value={[Math.min(rate, max)]} onValueChange={([v]) => setRate(v)} />
        </Field>
        <Field label={`Równoległe wątki: ${conc}`}>
          <Slider aria-label="Liczba równoległych wątków" disabled={!editable} min={1} max={128} step={1} value={[conc]} onValueChange={([v]) => setConc(v)} />
        </Field>
        <Field label="Tempo nmap" hint="T2 jest najłagodniejsze — zalecane dla drukarek, kamer i kontrolerów BMC.">
          <Segmented
            aria-label="Tempo nmap"
            value={timing}
            onChange={(v) => editable && setTiming(v)}
            options={[
              { value: "T2", label: "T2 — ostrożnie" },
              { value: "T3", label: "T3 — standard" },
              { value: "T4", label: "T4 — szybko" },
            ]}
          />
        </Field>
        <Field label={`Powtórne pomiary hostów niestabilnych: ${retries}`} hint="Ile razy ponowić pomiar, zanim zmiana zostanie uznana za pewną.">
          <Slider aria-label="Liczba powtórzeń" disabled={!editable} min={0} max={5} step={1} value={[retries]} onValueChange={([v]) => setRetries(v)} />
        </Field>
        <div className="grid gap-2">
          <label className="flex items-center justify-between gap-3 rounded-lg border border-line p-3 text-sm font-semibold">
            Odcisk HTTP/HTTPS (tytuł, nagłówki, ciasteczka, technologie)
            <Switch checked={http} disabled={!editable} onCheckedChange={setHttp} />
          </label>
          <label className="flex items-center justify-between gap-3 rounded-lg border border-line p-3 text-sm font-semibold">
            Certyfikaty TLS
            <Switch checked={tls} disabled={!editable} onCheckedChange={setTls} />
          </label>
        </div>
        <Field label="Sygnatury">
          <Segmented
            aria-label="Sygnatury"
            value={sigs}
            onChange={(v) => editable && setSigs(v)}
            options={[
              { value: "all", label: src.signatures === "selected" && !isNew ? `Wybrane (${src.signature_ids.length})` : "Wszystkie aktywne" },
              { value: "none", label: "Bez sygnatur" },
            ]}
          />
        </Field>
      </SheetBody>
      <SheetFooter className="justify-between">
        {!isNew && !src.builtin ? (
          <Guard permission="scans:delete">
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
          <Guard permission={isNew ? "scans:create" : "scans:update"}>
            <Button variant="primary" onClick={save} disabled={saving || !name.trim() || !portsOk}>
              {isNew ? "Utwórz profil" : "Zapisz profil"}
            </Button>
          </Guard>
        </div>
      </SheetFooter>
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={`Usunąć profil „${src.name}”?`}
        description="Profilu używanego przez harmonogram nie można usunąć. Tej operacji nie można cofnąć."
        confirmLabel="Usuń profil"
        onConfirm={async () => {
          setConfirmDelete(false);
          try {
            await api.profiles.remove(src.id);
            qc.invalidateQueries({ queryKey: ["profiles"] });
            toast.success("Usunięto profil", { description: src.name });
            onClose();
          } catch (e) {
            toast.error("Nie udało się usunąć profilu", { description: errorMessage(e) });
          }
        }}
      />
    </>
  );
}

export function ProfilesTab() {
  const q = useQuery({ queryKey: ["profiles"], queryFn: api.profiles.list });
  const can = useCan();
  const [mode, setMode] = React.useState<Mode | null>(null);
  const [last, setLast] = React.useState(mode);
  if (mode && mode !== last) setLast(mode);
  const base = q.data?.find((p) => p.id === "p-1") ?? q.data?.[0];

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-ink-2">Profil określa porty, tempo, timing nmap i zakres sprawdzeń. Żaden profil nie przekroczy globalnych limitów bezpieczeństwa.</p>
        <Guard permission="scans:create">
          <Button variant="primary" disabled={!base} onClick={() => base && setMode({ kind: "copy", profile: base })}>
            <Plus /> Nowy profil
          </Button>
        </Guard>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {(q.data ?? []).map((p) => (
          <article key={p.id} className="grid content-start gap-3 rounded-xl border border-line bg-surface p-5">
            <div className="flex items-start justify-between gap-3">
              <div className="grid gap-1">
                <h3 className="flex items-center gap-2 font-bold">
                  {p.name} {p.builtin ? <Chip tone="outline">wbudowany</Chip> : null}
                </h3>
                <p className="text-sm text-ink-2">{p.description}</p>
              </div>
              <Gauge className="size-5 shrink-0 text-ink-3" aria-hidden />
            </div>
            <div className="flex flex-wrap gap-1.5">
              <Chip>{fmtNumber(p.rate_limit_rps)} zapytań/s</Chip>
              <Chip>{p.max_concurrency} wątków</Chip>
              <Chip>nmap {p.nmap_timing}</Chip>
              <Chip>{portsLabel(p.ports)}</Chip>
              <Chip>{p.http_probe ? "HTTP/HTTPS" : "bez HTTP"}</Chip>
              <Chip>{p.signatures === "all" ? "wszystkie sygnatury" : p.signatures === "none" ? "bez sygnatur" : countLabel(p.signature_ids.length, ["sygnatura", "sygnatury", "sygnatur"])}</Chip>
              <Chip>podgrupy {p.batch_strategy === "auto" ? "automatyczne" : `/${p.batch_prefix}`}</Chip>
            </div>
            <div className="flex gap-2">
              <Button
                size="sm"
                onClick={() => setMode({ kind: "edit", profile: p })}
                aria-label={can("scans:update") ? `Edytuj profil ${p.name}` : `Szczegóły profilu ${p.name}`}
              >
                <Pencil /> {can("scans:update") ? "Edytuj" : "Szczegóły"}
              </Button>
              <Guard permission="scans:create">
                <Button size="sm" variant="ghost" onClick={() => setMode({ kind: "copy", profile: p })} aria-label={`Kopiuj profil ${p.name}`}>
                  <Copy /> Kopiuj
                </Button>
              </Guard>
            </div>
          </article>
        ))}
        {!q.data ? [0, 1].map((i) => <Skeleton key={i} className="h-48 rounded-xl" />) : null}
      </div>
      <Sheet open={Boolean(mode)} onOpenChange={(o) => !o && setMode(null)}>
        <SheetContent>{last ? <ProfileForm mode={last} onClose={() => setMode(null)} /> : null}</SheetContent>
      </Sheet>
    </div>
  );
}
