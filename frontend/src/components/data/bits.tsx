"use client";

import { Check, Copy, Pencil, RotateCcw, Search, TriangleAlert, X } from "lucide-react";
import * as React from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/form-controls";
import { Popover, PopoverContent, PopoverTrigger, Tooltip } from "@/components/ui/overlays";
import { errorMessage } from "@/lib/api/client";
import type { ManualOverride, Permission } from "@/lib/api/types";
import { fmtSmart } from "@/lib/format";
import { permissionLabel } from "@/lib/permissions";
import { useCan, useSession } from "@/lib/session";
import { cn, copyToClipboard } from "@/lib/utils";

/**
 * Machine value (IP, port, hash) in mono with a copy button on hover.
 * With `onActivate` the value itself is a link-style button (e.g. opens the editor).
 */
export function MonoValue({
  value,
  className,
  copy = true,
  onActivate,
  activateLabel,
}: {
  value: string;
  className?: string;
  copy?: boolean;
  onActivate?: () => void;
  activateLabel?: string;
}) {
  const [copied, setCopied] = React.useState(false);
  return (
    <span className={cn("group/mono inline-flex max-w-full items-center gap-1", className)}>
      {onActivate ? (
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onActivate();
          }}
          aria-label={activateLabel}
          className="mono truncate rounded-sm text-left underline-offset-2 hover:text-link hover:underline"
        >
          {value}
        </button>
      ) : (
        <span className="mono truncate">{value}</span>
      )}
      {copy ? (
        <button
          type="button"
          onClick={async (e) => {
            e.stopPropagation();
            if (await copyToClipboard(value)) {
              setCopied(true);
              setTimeout(() => setCopied(false), 1200);
            }
          }}
          className="rounded p-0.5 text-ink-3 opacity-0 transition-opacity group-hover/mono:opacity-100 hover:text-ink focus-visible:opacity-100"
          aria-label={`Kopiuj ${value}`}
        >
          {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
        </button>
      ) : null}
    </span>
  );
}

export function SearchInput({
  value,
  onChange,
  placeholder = "Szukaj…",
  className,
  "aria-label": ariaLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
  "aria-label"?: string;
}) {
  return (
    <div className={cn("relative", className)}>
      <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ink-3" aria-hidden />
      <Input
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel ?? placeholder}
        className="pl-9"
      />
      {value ? (
        <button
          type="button"
          onClick={() => onChange("")}
          className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-1 text-ink-3 hover:text-ink"
          aria-label="Wyczyść wyszukiwanie"
        >
          <X className="size-3.5" />
        </button>
      ) : null}
    </div>
  );
}

export function useDebouncedValue<T>(value: T, ms = 250) {
  const [v, setV] = React.useState(value);
  React.useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

export function EmptyState({
  title,
  description,
  action,
  icon,
  className,
}: {
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  icon?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("grid justify-items-start gap-1 px-5 py-8 text-left", className)}>
      {icon ? <span className="mb-1 text-ink-2 [&_svg]:size-5">{icon}</span> : null}
      <p className="text-sm font-semibold text-ink">{title}</p>
      {description ? <p className="max-w-[65ch] text-sm text-pretty text-ink-2">{description}</p> : null}
      {action ? <div className="mt-3">{action}</div> : null}
    </div>
  );
}

export function ErrorState({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  return (
    <div className={cn("flex flex-wrap items-center gap-3 rounded-xl border border-danger/40 bg-danger-soft px-4 py-3 text-sm text-danger", className)} role="alert">
      <TriangleAlert className="size-4 shrink-0" aria-hidden />
      <span className="flex-1">Nie udało się wczytać danych: {errorMessage(error)}</span>
      {onRetry ? (
        <Button size="sm" variant="secondary" onClick={onRetry}>
          Spróbuj ponownie
        </Button>
      ) : null}
    </div>
  );
}

/** Tags as plain text: "dmz, laboratorium +2". */
export function TagList({ tags, max = 3, className }: { tags: string[]; max?: number; className?: string }) {
  if (!tags.length) return <span className="text-ink-2">—</span>;
  return (
    <span className={cn("text-sm text-ink-2", className)} title={tags.length > max ? tags.join(", ") : undefined}>
      {tags.slice(0, max).join(", ")}
      {tags.length > max ? <span className="tabular"> +{tags.length - max}</span> : null}
    </span>
  );
}

/** Free-text tag editor (Enter / comma adds, Backspace removes). `mono` for machine values such as CIDR ranges. */
export function TagInput({
  value,
  onChange,
  suggestions = [],
  placeholder = "Dodaj tag i naciśnij Enter",
  id,
  mono,
}: {
  value: string[];
  onChange: (tags: string[]) => void;
  suggestions?: string[];
  placeholder?: string;
  id?: string;
  mono?: boolean;
}) {
  const [draft, setDraft] = React.useState("");
  const add = (raw: string) => {
    const t = raw.trim().toLowerCase().replace(/^#/, "").replace(/\s+/g, "-");
    if (t && !value.includes(t)) onChange([...value, t]);
    setDraft("");
  };
  const listId = id ? `${id}-suggestions` : undefined;
  return (
    <div className="flex min-h-9 flex-wrap items-center gap-1.5 rounded-lg border border-line-strong bg-surface px-2 py-1.5 focus-within:border-accent focus-within:ring-3 focus-within:ring-accent/25">
      {value.map((t) => (
        <span key={t} className={cn("inline-flex items-center gap-1 rounded-md bg-surface-3 py-0.5 pr-1 pl-1.5 text-xs text-ink contrast:border contrast:border-current", mono && "mono")}>
          {t}
          <button type="button" onClick={() => onChange(value.filter((x) => x !== t))} aria-label={`Usuń ${t}`} className="rounded p-0.5 text-ink-2 hover:text-ink">
            <X className="size-3" />
          </button>
        </span>
      ))}
      <input
        id={id}
        list={listId}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            add(draft);
          } else if (e.key === "Backspace" && !draft && value.length) onChange(value.slice(0, -1));
        }}
        onBlur={() => draft && add(draft)}
        placeholder={value.length ? "" : placeholder}
        className="min-w-28 flex-1 bg-transparent px-1 text-sm outline-none placeholder:text-ink-3"
      />
      {listId ? (
        <datalist id={listId}>
          {suggestions.filter((s) => !value.includes(s)).map((s) => (
            <option key={s} value={s} />
          ))}
        </datalist>
      ) : null}
    </div>
  );
}

/** Marks a value edited by a person — kept across future scans (requirement 14). */
export function ManualOverrideBadge({
  override,
  onRevert,
  canRevert,
  scannerLabel,
}: {
  override: ManualOverride | undefined;
  onRevert?: () => void;
  canRevert?: boolean;
  scannerLabel?: string;
}) {
  if (!override) return null;
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="inline-flex items-center gap-1 rounded-md bg-changed-soft px-1.5 py-0.5 text-xs font-semibold text-changed-ink hover:ring-1 hover:ring-changed contrast:border contrast:border-current"
        >
          <Pencil className="size-3" aria-hidden /> Edytowano ręcznie
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-80 text-sm">
        <p className="font-semibold">Wartość ustawiona ręcznie</p>
        <p className="mt-1 text-ink-2">
          {override.by}, {fmtSmart(override.at)}. Kolejne skany nie nadpiszą tej zmiany.
        </p>
        {override.scanner_value !== undefined ? (
          <p className="mt-2 rounded-lg bg-surface-2 px-2.5 py-2 text-sm">
            <span className="text-ink-2">Wartość ze skanu: </span>
            <span className="font-semibold">{scannerLabel ?? (String(override.scanner_value ?? "") || "—")}</span>
          </p>
        ) : null}
        {onRevert && canRevert ? (
          <Button size="sm" variant="secondary" className="mt-3" onClick={onRevert}>
            <RotateCcw /> Przywróć wartość ze skanu
          </Button>
        ) : null}
      </PopoverContent>
    </Popover>
  );
}

/** Renders children only when the user has the permission. */
export function Can({ permission, children, fallback = null }: { permission: Permission; children: React.ReactNode; fallback?: React.ReactNode }) {
  const can = useCan();
  return <>{can(permission) ? children : fallback}</>;
}

/**
 * Wraps an action control: when the role lacks the permission, the control is
 * disabled and a tooltip explains why (instead of silently hiding it).
 */
export function Guard({
  permission,
  children,
}: {
  permission: Permission;
  children: React.ReactElement<{ disabled?: boolean; className?: string; tabIndex?: number; onClick?: React.MouseEventHandler; "aria-disabled"?: boolean }>;
}) {
  const can = useCan();
  const session = useSession();
  if (can(permission)) return children;
  // Also blocks <Button asChild><Link/></Button>: anchors ignore the `disabled` attribute.
  const disabled = React.cloneElement(children, {
    disabled: true,
    "aria-disabled": true,
    tabIndex: -1,
    className: cn(children.props.className, "pointer-events-none opacity-50"),
    onClick: (e: React.MouseEvent) => e.preventDefault(),
  });
  return (
    <Tooltip content={`Twoja rola (${session.role.name}) nie ma uprawnienia „${permissionLabel(permission)}”.`}>
      <span tabIndex={0} className="inline-flex rounded-lg">
        {disabled}
      </span>
    </Tooltip>
  );
}
