"use client";

import { LoaderCircle } from "lucide-react";
import { Tabs as TabsPrimitive } from "radix-ui";
import * as React from "react";
import { cn } from "@/lib/utils";

export function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div aria-hidden className={cn("skeleton h-4 w-full", className)} {...props} />;
}

export function Spinner({ className }: { className?: string }) {
  return <LoaderCircle aria-hidden className={cn("size-4 animate-spin", className)} />;
}

export function Kbd({ className, ...props }: React.HTMLAttributes<HTMLElement>) {
  return (
    <kbd
      className={cn(
        "inline-flex h-5 min-w-5 items-center justify-center rounded border border-current/25 px-1 font-sans text-[0.6875rem] font-semibold opacity-80",
        className,
      )}
      {...props}
    />
  );
}

/** Neutral chip used for tags, technologies and counts. */
export function Chip({
  className,
  tone = "neutral",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { tone?: "neutral" | "outline" | "accent" | "danger" | "success" | "warning" }) {
  return (
    <span
      className={cn(
        "inline-flex max-w-full items-center gap-1 truncate rounded-md px-1.5 py-0.5 text-xs font-semibold",
        tone === "neutral" && "bg-surface-3 text-ink-2",
        tone === "outline" && "border border-line-strong text-ink-2",
        tone === "accent" && "bg-accent/12 text-link",
        tone === "danger" && "bg-danger-soft text-danger",
        tone === "success" && "bg-success-soft text-success",
        tone === "warning" && "bg-unstable-soft text-unstable-ink",
        "contrast:border contrast:border-current contrast:bg-transparent",
        className,
      )}
      {...props}
    />
  );
}

export function Progress({
  value,
  className,
  barClassName,
  label,
  indeterminate,
}: {
  value: number;
  className?: string;
  barClassName?: string;
  label?: string;
  indeterminate?: boolean;
}) {
  const pct = Math.max(0, Math.min(100, value * 100));
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={indeterminate ? undefined : Math.round(pct)}
      className={cn("relative h-2 w-full overflow-hidden rounded-full bg-surface-3", className)}
    >
      {indeterminate ? (
        <div className={cn("absolute inset-y-0 w-2/5 animate-indeterminate rounded-full bg-accent", barClassName)} />
      ) : (
        <div className={cn("h-full rounded-full bg-accent transition-[width] duration-700 ease-out", barClassName)} style={{ width: `${pct}%` }} />
      )}
    </div>
  );
}

export const Tabs = TabsPrimitive.Root;

export function TabsList({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.List>) {
  return <TabsPrimitive.List className={cn("flex gap-1 overflow-x-auto border-b border-line", className)} {...props} />;
}

export function TabsTrigger({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Trigger>) {
  return (
    <TabsPrimitive.Trigger
      className={cn(
        "relative -mb-px inline-flex h-10 shrink-0 items-center gap-2 border-b-2 border-transparent px-3 text-sm font-semibold text-ink-2 transition-colors hover:text-ink data-[state=active]:border-accent data-[state=active]:text-ink [&_svg]:size-4",
        className,
      )}
      {...props}
    />
  );
}

export function TabsContent({ className, ...props }: React.ComponentProps<typeof TabsPrimitive.Content>) {
  return <TabsPrimitive.Content className={cn("pt-5 outline-none", className)} {...props} />;
}

/** Section container on the light workspace. */
export function Panel({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
  id,
}: {
  title?: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  id?: string;
}) {
  return (
    <section id={id} className={cn("rounded-xl border border-line bg-surface", className)} aria-labelledby={id && title ? `${id}-title` : undefined}>
      {title || actions ? (
        <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-4">
          <div className="grid min-w-0 gap-0.5">
            {title ? (
              <h2 id={id ? `${id}-title` : undefined} className="text-base font-bold tracking-tight text-ink">
                {title}
              </h2>
            ) : null}
            {description ? <p className="text-[0.8125rem] text-ink-2">{description}</p> : null}
          </div>
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cn("p-5", bodyClassName)}>{children}</div>
    </section>
  );
}

/** Label/value rows for detail panels. */
export function DefinitionList({ items, className }: { items: { label: React.ReactNode; value: React.ReactNode }[]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-2.5 text-sm", className)}>
      {items.map((it, i) => (
        <React.Fragment key={i}>
          <dt className="text-ink-2">{it.label}</dt>
          <dd className="min-w-0 break-words text-ink">{it.value}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}
