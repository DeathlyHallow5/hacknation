"use client";

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, Pencil, RefreshCw } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { ErrorState, Guard, ManualOverrideBadge, MonoValue, TagInput, TagList } from "@/components/data/bits";
import { AvailabilityBadge, ChangeChip, ConfidenceMeter, ResponsePattern, ScoreMeter } from "@/components/data/status";
import { Container, PageHeader } from "@/components/layout/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/form-controls";
import { DefinitionList, Panel, Skeleton } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, Sheet, SheetBody, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { FieldDiff } from "@/components/viz/bits";
import { HttpFingerprintView } from "@/features/assets/http-fingerprint";
import { FindingDrawer } from "@/features/findings/finding-drawer";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Criticality, DeviceType, Host, Service } from "@/lib/api/types";
import { fmtPercent, fmtRelative, fmtSmart } from "@/lib/format";
import { useApiMutation } from "@/lib/hooks";
import { CRITICALITY_LABEL, DEVICE_LABEL, FINDING_CATEGORY_LABEL } from "@/lib/labels";
import { useCan } from "@/lib/session";
import { cn } from "@/lib/utils";

function EditHostSheet({ host, open, onOpenChange }: { host: Host; open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent>
        <EditHostForm host={host} onOpenChange={onOpenChange} />
      </SheetContent>
    </Sheet>
  );
}

function EditHostForm({ host, onOpenChange }: { host: Host; onOpenChange: (o: boolean) => void }) {
  const [owner, setOwner] = React.useState(host.owner ?? "");
  const [criticality, setCriticality] = React.useState<Criticality>(host.criticality);
  const [device, setDevice] = React.useState<DeviceType>(host.device_type);
  const [hostnames, setHostnames] = React.useState(host.hostnames.join("\n"));
  const [tags, setTags] = React.useState(host.tags);
  const [notes, setNotes] = React.useState(host.notes ?? "");
  const save = useApiMutation(
    () => {
      const body: Record<string, unknown> = {};
      if (owner !== (host.owner ?? "")) body.owner = owner || null;
      if (criticality !== host.criticality) body.criticality = criticality;
      if (device !== host.device_type) body.device_type = device;
      const hn = hostnames.split(/\s+/).filter(Boolean);
      if (JSON.stringify(hn) !== JSON.stringify(host.hostnames)) body.hostnames = hn;
      if (JSON.stringify(tags) !== JSON.stringify(host.tags)) body.tags = tags;
      if (notes !== (host.notes ?? "")) body.notes = notes || null;
      return api.hosts.update(host.id, body);
    },
    { success: "Zapisano. Zmiany zostaną zachowane przy kolejnych skanach", invalidate: [["host", host.id], ["hosts"]], onSuccess: () => onOpenChange(false) },
  );
  return (
    <>
        <SheetHeader>
          <SheetTitle>Edytuj dane hosta {host.ip}</SheetTitle>
          <SheetDescription>Wartości ustawione ręcznie mają pierwszeństwo przed wynikami skanu i nie zostaną nadpisane.</SheetDescription>
        </SheetHeader>
        <SheetBody>
          <form
            id="edit-host"
            className="grid gap-4"
            onSubmit={(e) => {
              e.preventDefault();
              save.mutate(undefined);
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Właściciel" htmlFor="h-owner">
                <Input id="h-owner" value={owner} onChange={(e) => setOwner(e.target.value)} />
              </Field>
              <Field label="Krytyczność">
                <SimpleSelect aria-label="Krytyczność" value={criticality} onChange={(v) => setCriticality((v || "medium") as Criticality)} options={(Object.keys(CRITICALITY_LABEL) as Criticality[]).map((c) => ({ value: c, label: CRITICALITY_LABEL[c] }))} />
              </Field>
            </div>
            <Field label="Typ urządzenia" hint="Popraw, jeśli skaner rozpoznał urządzenie błędnie.">
              <SimpleSelect aria-label="Typ urządzenia" value={device} onChange={(v) => setDevice((v || "unknown") as DeviceType)} options={(Object.keys(DEVICE_LABEL) as DeviceType[]).map((d) => ({ value: d, label: DEVICE_LABEL[d] }))} />
            </Field>
            <Field label="Nazwy hosta" htmlFor="h-names" hint="Po jednej w wierszu.">
              <Textarea id="h-names" className="mono min-h-20 text-sm" value={hostnames} onChange={(e) => setHostnames(e.target.value)} />
            </Field>
            <Field label="Tagi" htmlFor="h-tags">
              <TagInput id="h-tags" value={tags} onChange={setTags} />
            </Field>
            <Field label="Notatki" htmlFor="h-notes" hint="Notatki są szyfrowane w bazie danych.">
              <Textarea id="h-notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Np. host serwisowany przez firmę zewnętrzną, kontakt: …" />
            </Field>
          </form>
        </SheetBody>
        <SheetFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Anuluj
          </Button>
          <Button type="submit" form="edit-host" variant="primary" disabled={save.isPending}>
            Zapisz zmiany
          </Button>
        </SheetFooter>
    </>
  );
}

function FixServiceDialog({ service, onClose, hostId }: { service: Service | null; onClose: () => void; hostId: string }) {
  const [last, setLast] = React.useState(service);
  if (service && service !== last) setLast(service);
  return (
    <Dialog open={Boolean(service)} onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="sm">{last ? <FixServiceForm service={last} onClose={onClose} hostId={hostId} /> : null}</DialogContent>
    </Dialog>
  );
}

function FixServiceForm({ service, onClose, hostId }: { service: Service; onClose: () => void; hostId: string }) {
  const [product, setProduct] = React.useState(service.product ?? "");
  const [version, setVersion] = React.useState(service.version ?? "");
  const save = useApiMutation(() => api.services.update(service.id, { product: product || null, version: version || null }), {
    success: "Poprawiono identyfikację usługi",
    invalidate: [["host", hostId], ["services"]],
    onSuccess: onClose,
  });
  return (
    <>
        <DialogHeader>
          <DialogTitle>Popraw identyfikację usługi</DialogTitle>
          <DialogDescription>
            Port {service.port}/{service.protocol}. Skaner nie nadpisze ręcznie ustawionego produktu i wersji.
          </DialogDescription>
        </DialogHeader>
        <Field label="Produkt" htmlFor="svc-product">
          <Input id="svc-product" value={product} onChange={(e) => setProduct(e.target.value)} />
        </Field>
        <Field label="Wersja" htmlFor="svc-version">
          <Input id="svc-version" value={version} onChange={(e) => setVersion(e.target.value)} className="mono" />
        </Field>
        <DialogFooter>
          <Button variant="secondary" onClick={onClose}>
            Anuluj
          </Button>
          <Button variant="primary" onClick={() => save.mutate(undefined)} disabled={save.isPending}>
            Zapisz
          </Button>
        </DialogFooter>
    </>
  );
}

function ServiceCard({ s, onFix, defaultOpen }: { s: Service; onFix: () => void; defaultOpen: boolean }) {
  const [open, setOpen] = React.useState(defaultOpen);
  const isRedirect = s.http?.status_code === 301 && !s.http.technologies.some((t) => t.category !== "web_server");
  /* A row of the services list, not a card: the panel is the only frame. */
  return (
    <li id={`svc-${s.port}`} className="scroll-mt-32">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3">
        <span className="mono w-24 shrink-0 text-sm font-semibold">
          {s.port}/{s.protocol}
        </span>
        <span className="grid min-w-0 flex-1 gap-0.5">
          <span className="flex flex-wrap items-center gap-2 font-semibold">
            {s.product ?? s.name}
            {s.version ? <span className="mono text-sm font-normal text-ink-2">{s.version}</span> : null}
            {s.change !== "unchanged" ? <ChangeChip state={s.change} /> : null}
            <ManualOverrideBadge override={s.manual_overrides.version ?? s.manual_overrides.product} />
          </span>
          <span className="text-xs text-pretty text-ink-2">
            {s.name}
            {s.tls ? ", TLS" : ""}
            {s.http?.title && !isRedirect ? `, „${s.http.title}”` : isRedirect ? ", przekierowanie na HTTPS" : ""}
          </span>
          {s.banner ? <span className="mono truncate text-xs text-ink-2">{s.banner}</span> : null}
        </span>
        {/* Fixed-width slots on the right, so confidence and actions line up from row to row. */}
        <span className="flex shrink-0 items-center gap-2">
          <span className="w-10 text-right" title="Pewność identyfikacji usługi">
            <ConfidenceMeter value={s.confidence} compact valueClassName="text-ink-2" />
          </span>
          <Guard permission="assets:update">
            <Button size="icon-sm" variant="ghost" aria-label={`Popraw identyfikację portu ${s.port}`} onClick={onFix}>
              <Pencil />
            </Button>
          </Guard>
          <span className="flex w-36 justify-end">
            {s.http ? (
              <Button size="sm" variant="ghost" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
                Odcisk HTTP <ChevronDown className={cn("transition-transform", open && "rotate-180")} />
              </Button>
            ) : null}
          </span>
        </span>
      </div>
      {open && s.http ? (
        <div className="px-5 pt-1 pb-5 sm:pl-[8.25rem]">
          <HttpFingerprintView http={s.http} serviceId={s.id} />
        </div>
      ) : null}
    </li>
  );
}

export function HostView({ id }: { id: string }) {
  const qc = useQueryClient();
  const can = useCan();
  const q = useQuery({ queryKey: ["host", id], queryFn: () => api.hosts.get(id), refetchInterval: (query) => (query.state.data && query.state.data.availability === "unstable" ? 7000 : false) });
  const history = useQuery({ queryKey: ["host-history", id], queryFn: () => api.hosts.history(id) });
  const findings = useQuery({ queryKey: ["findings", "host", id], queryFn: () => api.findings.list({ host_id: id, page_size: 20 }), enabled: can("findings:read") });
  const [editOpen, setEditOpen] = React.useState(false);
  const [fixing, setFixing] = React.useState<Service | null>(null);
  const [openFinding, setOpenFinding] = React.useState<string | null>(null);
  const [hash] = React.useState(() => (typeof window === "undefined" ? "" : window.location.hash));

  if (q.isError) return <Container className="py-8"><ErrorState error={q.error} onRetry={() => q.refetch()} /></Container>;
  const h = q.data;
  if (!h) return <Container className="grid gap-4 py-8"><Skeleton className="h-10 w-72" /><Skeleton className="h-80" /></Container>;

  const revert = async (field: string) => {
    try {
      await api.hosts.revert(h.id, field);
      qc.invalidateQueries({ queryKey: ["host", id] });
      toast.success("Przywrócono wartość ze skanu");
    } catch (e) {
      toast.error("Nie udało się przywrócić", { description: errorMessage(e) });
    }
  };
  const recheck = async () => {
    try {
      await api.hosts.recheck(h.id);
      toast.success("Zlecono ponowny pomiar", { description: "Wynik pojawi się w historii pomiarów za kilka sekund." });
      setTimeout(() => qc.invalidateQueries({ queryKey: ["host", id] }), 6500);
    } catch (e) {
      toast.error("Nie udało się zlecić pomiaru", { description: errorMessage(e) });
    }
  };
  const ov = h.manual_overrides;
  const ovBadge = (field: string, label?: string) => (
    <ManualOverrideBadge override={ov[field]} canRevert={can("assets:update")} onRevert={() => revert(field)} scannerLabel={label} />
  );

  return (
    <Container className="pb-12">
      <PageHeader
        back={{ href: "/assets", label: "Zasoby" }}
        title={<MonoValue value={h.ip} className="text-[1.75rem]" />}
        description={h.hostnames.length ? h.hostnames.join(", ") : "Brak nazwy w DNS"}
        meta={
          <>
            <AvailabilityBadge value={h.availability} missCount={h.miss_count} />
            {h.change !== "unchanged" ? <ChangeChip state={h.change} /> : null}
            {/* Facts are separated by hairlines, the same way everywhere, instead of a lone middle dot. */}
            <span className="border-l border-line pl-3">{DEVICE_LABEL[h.device_type]}</span>
            <span className="border-l border-line pl-3">Krytyczność: {CRITICALITY_LABEL[h.criticality].toLowerCase()}</span>
            <span className="mono border-l border-line pl-3">{h.subnet}</span>
          </>
        }
        actions={
          <>
            <Guard permission="assets:recheck">
              <Button onClick={recheck}>
                <RefreshCw /> Ponów pomiar
              </Button>
            </Guard>
            <Guard permission="assets:update">
              <Button variant="primary" onClick={() => setEditOpen(true)}>
                <Pencil /> Edytuj dane
              </Button>
            </Guard>
          </>
        }
      />
      <div className="grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_24rem]">
        <div className="grid gap-6">
          <Panel title={`Usługi (${h.services.length})`} flush>
            {h.services.length ? (
              <ul className="divide-y divide-line">
                {h.services.map((s) => (
                  <ServiceCard key={s.id} s={s} onFix={() => setFixing(s)} defaultOpen={hash === `#svc-${s.port}` || (h.services.filter((x) => x.http).length === 1 && Boolean(s.http))} />
                ))}
              </ul>
            ) : (
              <p className="px-5 py-4 text-sm text-ink-2">Host odpowiada na ping, ale nie ma otwartych portów z profilu skanowania.</p>
            )}
          </Panel>
          {can("findings:read") ? (
            <Panel title={`Znaleziska (${findings.data?.total ?? "…"})`} flush>
              <ul className="divide-y divide-line">
                {(findings.data?.items ?? []).map((f) => (
                  <li key={f.id}>
                    <button type="button" onClick={() => setOpenFinding(f.id)} className="flex w-full items-center gap-3 px-5 py-3 text-left hover:bg-surface-2">
                      <span className="grid flex-1 gap-0.5">
                        <span className="font-semibold">{f.title}</span>
                        <span className="text-xs text-ink-2">
                          {FINDING_CATEGORY_LABEL[f.category]}
                          {f.service_label ? `, ${f.service_label}` : ""}
                        </span>
                      </span>
                      <ScoreMeter score={f.score_override ?? f.score} />
                    </button>
                  </li>
                ))}
                {findings.data && !findings.data.items.length ? <li className="px-5 py-4 text-sm text-ink-2">Brak znalezisk dla tego hosta.</li> : null}
              </ul>
            </Panel>
          ) : null}
        </div>

        <div className="grid gap-6">
          <Panel title="Dane hosta">
            <DefinitionList
              items={[
                { label: "Właściciel", value: <span className="flex flex-wrap items-center gap-2">{h.owner ?? "—"} {ovBadge("owner")}</span> },
                { label: "Krytyczność", value: <span className="flex flex-wrap items-center gap-2">{CRITICALITY_LABEL[h.criticality]} {ovBadge("criticality", ov.criticality ? CRITICALITY_LABEL[ov.criticality.scanner_value as Criticality] : undefined)}</span> },
                { label: "Typ urządzenia", value: <span className="flex flex-wrap items-center gap-2">{DEVICE_LABEL[h.device_type]} {ovBadge("device_type", ov.device_type ? DEVICE_LABEL[ov.device_type.scanner_value as DeviceType] : undefined)}</span> },
                { label: "System", value: h.os_guess ?? "—" },
                { label: "Tagi", value: <span className="flex flex-wrap items-center gap-2"><TagList tags={h.tags} max={6} /> {ovBadge("tags")}</span> },
                { label: "Pierwsze wykrycie", value: fmtSmart(h.first_seen) },
                { label: "Ostatnio widziany", value: fmtSmart(h.last_seen) },
                { label: "Notatki", value: <span className="flex flex-wrap items-center gap-2 whitespace-pre-wrap">{h.notes ?? "—"} {ovBadge("notes")}</span> },
              ]}
            />
          </Panel>
          <Panel title="Dostępność" description="Od najstarszego pomiaru">
            <div className="grid gap-3">
              <ResponsePattern pattern={h.response_pattern} className="[&>span]:size-3" />
              <p className="text-sm text-pretty">
                Odpowiedział w <span className="font-semibold">{h.response_pattern.filter(Boolean).length}</span> z {h.response_pattern.length} pomiarów (
                {fmtPercent(h.response_pattern.filter(Boolean).length / h.response_pattern.length)}).
                {h.miss_count ? ` Bez odpowiedzi od ${h.miss_count} ${h.miss_count === 1 ? "skanu" : "skanów"}.` : ""} Host staje się nieaktywny po 3 kolejnych skanach bez
                odpowiedzi.
              </p>
            </div>
          </Panel>
          <Panel title="Historia zmian">
            <ol className="grid gap-4">
              {(history.data ?? []).map((e) => (
                <li key={e.scan_id} className="grid grid-cols-[auto_1fr] gap-3">
                  <span className={cn("mt-1 size-2.5 rounded-full", e.responded ? "bg-data" : "border-[1.5px] border-ink-3")} aria-hidden />
                  <div className="grid gap-1">
                    <span className="text-sm">
                      <span className="font-semibold">Skan #{e.scan_number}</span>
                      <span className="text-ink-2">, {fmtRelative(e.at)}</span>
                    </span>
                    <span className="text-xs text-ink-2">
                      {e.responded ? (
                        e.open_ports.length ? (
                          <>
                            Porty: <span className="mono text-ink">{e.open_ports.join(", ")}</span>
                          </>
                        ) : (
                          "Odpowiada"
                        )
                      ) : (
                        "Brak odpowiedzi"
                      )}
                    </span>
                    {e.changes.length ? <FieldDiff fields={e.changes} /> : null}
                  </div>
                </li>
              ))}
              {!history.data ? <Skeleton className="h-32" /> : null}
            </ol>
          </Panel>
        </div>
      </div>
      <EditHostSheet host={h} open={editOpen} onOpenChange={setEditOpen} />
      <FixServiceDialog service={fixing} onClose={() => setFixing(null)} hostId={h.id} />
      <FindingDrawer id={openFinding} onOpenChange={(o) => !o && setOpenFinding(null)} />
    </Container>
  );
}
