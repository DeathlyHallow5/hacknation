"use client";

import { Check, ChevronDown } from "lucide-react";
import { Select as SelectPrimitive } from "radix-ui";
import * as React from "react";
import { cn } from "@/lib/utils";

export const Select = SelectPrimitive.Root;
export const SelectValue = SelectPrimitive.Value;
export const SelectGroup = SelectPrimitive.Group;

/** `quiet`: an inline editor inside a table row; reads as text until hovered or focused. */
export function SelectTrigger({ className, children, quiet, ...props }: React.ComponentProps<typeof SelectPrimitive.Trigger> & { quiet?: boolean }) {
  return (
    <SelectPrimitive.Trigger
      className={cn(
        "inline-flex h-9 w-full items-center justify-between gap-2 rounded-lg border border-line-strong bg-field px-3 text-left text-sm text-ink transition-colors hover:border-ink-3 focus-visible:border-accent focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-accent/25 disabled:cursor-not-allowed disabled:opacity-60 data-[placeholder]:text-ink-3 [&>span]:truncate",
        quiet && "-ml-2 border-transparent bg-transparent px-2 hover:border-line-strong focus-visible:border-accent",
        className,
      )}
      {...props}
    >
      {children}
      <SelectPrimitive.Icon asChild>
        <ChevronDown className={cn("size-4 shrink-0", quiet ? "text-ink-3" : "text-ink-2")} />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  );
}

export function SelectContent({ className, children, position = "popper", ...props }: React.ComponentProps<typeof SelectPrimitive.Content>) {
  return (
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        position={position}
        sideOffset={6}
        className={cn(
          "relative z-50 max-h-[min(24rem,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-xl border border-line bg-surface text-ink shadow-pop data-[state=open]:animate-in data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 data-[state=closed]:animate-out data-[state=closed]:fade-out-0",
          className,
        )}
        {...props}
      >
        <SelectPrimitive.Viewport className="scroll-quiet p-1">{children}</SelectPrimitive.Viewport>
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  );
}

export function SelectItem({ className, children, ...props }: React.ComponentProps<typeof SelectPrimitive.Item>) {
  return (
    <SelectPrimitive.Item
      className={cn(
        "relative flex w-full cursor-default items-center rounded-md py-2 pr-8 pl-2.5 text-sm outline-none select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[highlighted]:bg-surface-3 contrast:data-[highlighted]:outline contrast:data-[highlighted]:outline-1 contrast:data-[highlighted]:outline-accent",
        className,
      )}
      {...props}
    >
      <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
      <SelectPrimitive.ItemIndicator className="absolute right-2.5 inline-flex">
        <Check className="size-4 text-link" />
      </SelectPrimitive.ItemIndicator>
    </SelectPrimitive.Item>
  );
}

export function SelectLabel({ className, ...props }: React.ComponentProps<typeof SelectPrimitive.Label>) {
  return <SelectPrimitive.Label className={cn("px-2.5 pt-2 pb-1 text-xs font-semibold text-ink-2", className)} {...props} />;
}

/** Convenience select bound to a list of options. "" maps to "all". */
export function SimpleSelect<T extends string>({
  value,
  onChange,
  options,
  placeholder,
  className,
  allLabel,
  "aria-label": ariaLabel,
  disabled,
  quiet,
}: {
  value: T | "";
  onChange: (v: T | "") => void;
  options: { value: T; label: string }[];
  placeholder?: string;
  className?: string;
  allLabel?: string;
  "aria-label"?: string;
  disabled?: boolean;
  quiet?: boolean;
}) {
  const ALL = "__all__";
  return (
    <Select value={value || (allLabel ? ALL : undefined)} onValueChange={(v) => onChange(v === ALL ? "" : (v as T))} disabled={disabled}>
      <SelectTrigger className={className} aria-label={ariaLabel} quiet={quiet}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {allLabel ? <SelectItem value={ALL}>{allLabel}</SelectItem> : null}
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
