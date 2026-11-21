"use client";

import { CircleCheck, CircleX, Info } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { TagInput } from "@/components/data/bits";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/form-controls";
import { Chip } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/overlays";
import { SimpleSelect } from "@/components/ui/select";
import { errorMessage } from "@/lib/api/client";
import { api } from "@/lib/api/endpoints";
import type { Criticality } from "@/lib/api/types";
import { countLabel, fmtNumber } from "@/lib/format";
import { CRITICALITY_LABEL, TARGET_TYPE_LABEL } from "@/lib/labels";
import { checkTarget, splitEntries } from "@/lib/net";
import { useQueryClient } from "@tanstack/react-query";

const EXAMPLE = "10.0.32.0/22\nportal.wydzial.uczelnia.example\n10.0.40.66\n300.1.1.1";

export function AddTargetsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <AddTargetsForm onOpenChange={onOpenChange} />
      </DialogContent>
    </Dialog>
  );
}

/** Inside DialogContent: unmounted on close, so every opening starts empty. */
function AddTargetsForm({ onOpenChange }: { onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const [text, setText] = React.useState("");
  const [name, setName] = React.useState("");
  const [owner, setOwner] = React.useState("");
  const [criticality, setCriticality] = React.useState<Criticality>("medium");
  const [tags, setTags] = React.useState<string[]>([]);
  const [pending, setPending] = React.useState(false);

  const entries = splitEntries(text);
  const checks = entries.map(checkTarget);
  const seen = new Set<string>();
  const rows = checks.map((c) => {
    const dup = c.ok && seen.has(c.value!);
    if (c.ok) seen.add(c.value!);
    return { ...c, dup };
  });
  const valid = rows.filter((r) => r.ok && !r.dup);
  const invalid = rows.filter((r) => !r.ok);
  const addresses = valid.reduce((n, r) => n + (r.address_count ?? 0), 0);

  const submit = async () => {
    setPending(true);
    try {
      const res = await api.targets.create({
        items: valid.map((r) => ({ value: r.value!, name: name || null, owner: owner || null, criticality, tags })),
      });
      qc.invalidateQueries({ queryKey: ["targets"] });
      toast.success(`Dodano ${countLabel(res.created.length, ["cel", "cele", "celów"])}`, {
        description: res.skipped.length ? `Pominięto ${res.skipped.length}: ${res.skipped[0].reason.toLowerCase()}.` : "Zostaną uwzględnione w najbliższym skanowaniu.",
      });
      onOpenChange(false);
    } catch (e) {
      toast.error("Nie udało się dodać celów", { description: errorMessage(e) });
    } finally {
      setPending(false);
    }
  };

  return (
    <>
        <DialogHeader>
          <DialogTitle>Dodaj cele ręcznie</DialogTitle>
          <DialogDescription>
            Wklej adresy IP, zakresy CIDR lub domeny — po jednym w wierszu albo oddzielone przecinkami. Każdy wpis sprawdzamy tak samo jak przy imporcie z pliku.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-5 lg:grid-cols-[1fr_1fr]">
          <div className="grid content-start gap-4">
            <Field label="Cele" htmlFor="targets-text" aside={<button type="button" className="text-[0.8125rem] font-semibold text-link hover:underline" onClick={() => setText(EXAMPLE)}>Wstaw przykład</button>}>
              <Textarea
                id="targets-text"
                value={text}
                onChange={(e) => setText(e.target.value)}
                className="mono min-h-48 text-[0.8125rem]"
                placeholder={"10.0.0.0/24\n10.0.5.17\nportal.uczelnia.example"}
                spellCheck={false}
              />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Nazwa (opcjonalnie)" htmlFor="t-name">
                <Input id="t-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Np. Pracownia sieciowa" />
              </Field>
              <Field label="Właściciel" htmlFor="t-owner">
                <Input id="t-owner" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Np. Wydział Informatyki" />
              </Field>
              <Field label="Krytyczność">
                <SimpleSelect
                  aria-label="Krytyczność"
                  value={criticality}
                  onChange={(v) => setCriticality((v || "medium") as Criticality)}
                  options={(Object.keys(CRITICALITY_LABEL) as Criticality[]).map((c) => ({ value: c, label: CRITICALITY_LABEL[c] }))}
                />
              </Field>
              <Field label="Tagi" htmlFor="t-tags">
                <TagInput id="t-tags" value={tags} onChange={setTags} suggestions={["dmz", "laboratorium", "wydziały", "iot"]} />
              </Field>
            </div>
          </div>
          <div className="grid content-start gap-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-bold">Podgląd ({entries.length})</span>
              <span className="text-[0.8125rem] text-ink-2">
                {valid.length} poprawnych, {invalid.length} błędnych, {fmtNumber(addresses)} adresów
              </span>
            </div>
            <div className="scroll-quiet max-h-80 min-h-48 overflow-y-auto rounded-lg border border-line">
              {rows.length === 0 ? (
                <p className="flex items-start gap-2 p-4 text-sm text-ink-2">
                  <Info className="mt-0.5 size-4 shrink-0" aria-hidden /> Tutaj zobaczysz wynik walidacji każdego wpisu: typ, liczbę adresów i ewentualny błąd.
                </p>
              ) : (
                <ul className="divide-y divide-line text-sm">
                  {rows.map((r, i) => (
                    <li key={i} className="flex items-start gap-2.5 px-3 py-2">
                      {r.ok && !r.dup ? <CircleCheck className="mt-0.5 size-4 shrink-0 text-success" aria-label="poprawny" /> : <CircleX className="mt-0.5 size-4 shrink-0 text-danger" aria-label="błąd" />}
                      <span className="grid min-w-0 gap-0.5">
                        <span className="mono truncate font-semibold">{r.input}</span>
                        <span className="text-xs text-ink-2">
                          {r.ok
                            ? r.dup
                              ? "Powtórzony wpis — zostanie pominięty"
                              : `${TARGET_TYPE_LABEL[r.type!]}${r.type === "cidr" ? `, ${fmtNumber(r.address_count!)} adresów` : ""}${r.note ? `. ${r.note}` : ""}`
                            : r.error}
                        </span>
                      </span>
                      {r.ok && !r.dup ? <Chip className="ml-auto">{TARGET_TYPE_LABEL[r.type!]}</Chip> : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Anuluj
          </Button>
          <Button variant="primary" disabled={!valid.length || pending} onClick={submit}>
            Dodaj {valid.length ? countLabel(valid.length, ["cel", "cele", "celów"]) : "cele"}
          </Button>
        </DialogFooter>
    </>
  );
}
