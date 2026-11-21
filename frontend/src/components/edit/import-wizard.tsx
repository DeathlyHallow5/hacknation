"use client";

import { CircleCheck, CircleX, Copy, FileJson, FileSpreadsheet, FileUp, Upload } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Segmented } from "@/components/ui/form-controls";
import { Chip, Spinner } from "@/components/ui/misc";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/overlays";
import { errorMessage } from "@/lib/api/client";
import type { ImportReport } from "@/lib/api/types";
import { fmtBytes, fmtNumber } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface ImportWizardProps {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  description: React.ReactNode;
  samples: { label: string; href: string }[];
  formatHint: React.ReactNode;
  /** Dry run (preview). Return null when the endpoint has no preview. */
  preview?: (form: FormData) => Promise<ImportReport>;
  commit: (form: FormData) => Promise<string>;
  conflictOption?: boolean;
}

/** Drag & drop CSV/JSON import with server-side validation preview. */
export function ImportWizard({ open, onOpenChange, title, description, samples, formatHint, preview, commit, conflictOption }: ImportWizardProps) {
  const [file, setFile] = React.useState<File | null>(null);
  const [drag, setDrag] = React.useState(false);
  const [report, setReport] = React.useState<ImportReport | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState<"preview" | "commit" | null>(null);
  const [onConflict, setOnConflict] = React.useState<"skip" | "update">("skip");
  const inputRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    if (!open) {
      setFile(null);
      setReport(null);
      setError(null);
      setBusy(null);
    }
  }, [open]);

  const makeForm = (dryRun: boolean, f: File) => {
    const fd = new FormData();
    fd.set("file", f);
    fd.set("dry_run", String(dryRun));
    fd.set("on_conflict", onConflict);
    return fd;
  };

  const pick = async (f: File | undefined | null) => {
    if (!f) return;
    setFile(f);
    setReport(null);
    setError(null);
    if (!preview) return;
    setBusy("preview");
    try {
      setReport(await preview(makeForm(true, f)));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  React.useEffect(() => {
    if (file && preview && open) void pick(file);
    // re-run preview when the conflict policy changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onConflict]);

  const doCommit = async () => {
    if (!file) return;
    setBusy("commit");
    setError(null);
    try {
      await commit(makeForm(false, file));
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
      setBusy(null);
    }
  };

  const isJson = file?.name.toLowerCase().endsWith(".json");

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>

        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDrag(false);
            void pick(e.dataTransfer.files?.[0]);
          }}
          className={cn(
            "grid place-items-center gap-2 rounded-xl border-2 border-dashed px-6 py-8 text-center transition-colors",
            drag ? "border-accent bg-accent/[0.06]" : "border-line-strong bg-surface-2",
          )}
        >
          {file ? (
            <div className="flex items-center gap-3">
              {isJson ? <FileJson className="size-8 text-link" aria-hidden /> : <FileSpreadsheet className="size-8 text-link" aria-hidden />}
              <div className="grid text-left">
                <span className="font-semibold">{file.name}</span>
                <span className="text-[0.8125rem] text-ink-2">{fmtBytes(file.size)}</span>
              </div>
              <Button size="sm" variant="ghost" onClick={() => inputRef.current?.click()}>
                Zmień plik
              </Button>
            </div>
          ) : (
            <>
              <Upload className="size-7 text-ink-3" aria-hidden />
              <p className="text-sm">
                <span className="font-semibold">Przeciągnij plik CSV lub JSON</span> albo{" "}
                <button type="button" className="font-semibold text-link hover:underline" onClick={() => inputRef.current?.click()}>
                  wybierz z dysku
                </button>
              </p>
              <p className="text-[0.8125rem] text-ink-2">{formatHint}</p>
            </>
          )}
          <input ref={inputRef} type="file" accept=".csv,.json,text/csv,application/json" className="sr-only" onChange={(e) => pick(e.target.files?.[0])} />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 text-[0.8125rem] text-ink-2">
            Przykładowe pliki:
            {samples.map((s) => (
              <a key={s.href} href={s.href} download className="inline-flex items-center gap-1 font-semibold text-link hover:underline">
                <Copy className="size-3.5" aria-hidden /> {s.label}
              </a>
            ))}
          </div>
          {conflictOption ? (
            <label className="flex items-center gap-2 text-[0.8125rem]">
              <span className="text-ink-2">Gdy cel już istnieje</span>
              <Segmented
                size="sm"
                aria-label="Postępowanie z duplikatami"
                value={onConflict}
                onChange={setOnConflict}
                options={[
                  { value: "skip", label: "Pomiń" },
                  { value: "update", label: "Zaktualizuj" },
                ]}
              />
            </label>
          ) : null}
        </div>

        {busy === "preview" ? (
          <p className="flex items-center gap-2 text-sm text-ink-2">
            <Spinner /> Sprawdzamy plik…
          </p>
        ) : null}
        {error ? (
          <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm font-semibold text-danger">
            {error}
          </p>
        ) : null}

        {report ? (
          <div className="grid gap-3">
            <div className="flex flex-wrap gap-2">
              <Chip tone="success">{fmtNumber(report.valid)} do zaimportowania</Chip>
              {report.created ? <Chip tone="accent">{fmtNumber(report.created)} nowych</Chip> : null}
              {report.updated ? <Chip tone="accent">{fmtNumber(report.updated)} do aktualizacji</Chip> : null}
              {report.duplicates ? <Chip tone="warning">{fmtNumber(report.duplicates)} duplikatów</Chip> : null}
              {report.invalid ? <Chip tone="danger">{fmtNumber(report.invalid)} błędnych</Chip> : null}
              <Chip tone="outline">{report.format.toUpperCase()}, {fmtNumber(report.total_rows)} wierszy</Chip>
            </div>
            <div className="scroll-quiet max-h-64 overflow-auto rounded-lg border border-line">
              <table className="w-full text-sm">
                <thead className="sticky top-0 bg-surface-2 text-left text-[0.8125rem] text-ink-2">
                  <tr>
                    <th className="w-16 px-3 py-2 font-semibold">Wiersz</th>
                    <th className="px-3 py-2 font-semibold">Wartość</th>
                    <th className="px-3 py-2 font-semibold">Wynik</th>
                  </tr>
                </thead>
                <tbody>
                  {report.rows.map((r) => (
                    <tr key={r.row} className="border-t border-line">
                      <td className="tabular px-3 py-1.5 text-ink-2">{r.row}</td>
                      <td className="mono px-3 py-1.5">{r.value || "—"}</td>
                      <td className="px-3 py-1.5">
                        <span className={cn("inline-flex items-center gap-1.5 text-[0.8125rem]", r.status === "ok" ? "text-success" : r.status === "duplicate" ? "text-unstable-ink" : "text-danger")}>
                          {r.status === "ok" ? <CircleCheck className="size-3.5" aria-hidden /> : <CircleX className="size-3.5" aria-hidden />}
                          {r.status === "ok" ? `OK${r.address_count && r.address_count > 1 ? `, ${fmtNumber(r.address_count)} adresów` : ""}` : r.error}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : null}

        <DialogFooter>
          <Button variant="secondary" onClick={() => onOpenChange(false)}>
            Anuluj
          </Button>
          <Button variant="primary" disabled={!file || busy !== null || (report !== null && report.valid === 0)} onClick={doCommit}>
            {busy === "commit" ? <Spinner /> : <FileUp />} Importuj
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
