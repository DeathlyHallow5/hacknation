"use client";

import { Check, Minus } from "lucide-react";
import { Checkbox as CheckboxPrimitive, Label as LabelPrimitive, RadioGroup, Slider as SliderPrimitive, Switch as SwitchPrimitive } from "radix-ui";
import * as React from "react";
import { cn } from "@/lib/utils";

const fieldBase =
  "w-full rounded-lg border border-line-strong bg-field text-ink placeholder:text-ink-3 transition-colors hover:border-ink-3 focus-visible:border-accent focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-accent/25 disabled:cursor-not-allowed disabled:opacity-60 aria-invalid:border-danger aria-invalid:ring-danger/20 contrast:focus-visible:ring-0";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input ref={ref} className={cn(fieldBase, "h-9 px-3 text-sm", className)} {...props} />
  ),
);
Input.displayName = "Input";

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea ref={ref} className={cn(fieldBase, "min-h-24 px-3 py-2 text-sm leading-relaxed", className)} {...props} />
  ),
);
Textarea.displayName = "Textarea";

export function Label({ className, ...props }: React.ComponentProps<typeof LabelPrimitive.Root>) {
  return <LabelPrimitive.Root className={cn("text-sm font-semibold text-ink", className)} {...props} />;
}

export function Field({
  label,
  hint,
  error,
  htmlFor,
  children,
  className,
  aside,
}: {
  label: React.ReactNode;
  hint?: React.ReactNode;
  error?: string | null;
  htmlFor?: string;
  children: React.ReactNode;
  className?: string;
  aside?: React.ReactNode;
}) {
  return (
    <div className={cn("grid gap-1.5", className)}>
      <div className="flex items-baseline justify-between gap-3">
        <Label htmlFor={htmlFor}>{label}</Label>
        {aside}
      </div>
      {children}
      {error ? (
        <p className="text-sm font-medium text-danger" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p className="text-sm text-ink-2">{hint}</p>
      ) : null}
    </div>
  );
}

export function Checkbox({
  className,
  checked,
  ...props
}: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      checked={checked}
      className={cn(
        "peer grid size-[1.125rem] shrink-0 place-items-center rounded-[5px] border border-line-strong bg-surface text-accent-ink transition-colors hover:border-ink-3 data-[state=checked]:border-accent data-[state=checked]:bg-accent data-[state=indeterminate]:border-accent data-[state=indeterminate]:bg-accent",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator>
        {checked === "indeterminate" ? <Minus className="size-3.5" strokeWidth={3} /> : <Check className="size-3.5" strokeWidth={3} />}
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

export function Switch({ className, ...props }: React.ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      className={cn(
        "relative inline-flex h-6 w-10 shrink-0 cursor-pointer items-center rounded-full border border-line-strong bg-surface-3 transition-colors data-[state=checked]:border-accent data-[state=checked]:bg-accent disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb className="pointer-events-none block size-[1.125rem] translate-x-0.5 rounded-full bg-white shadow-sm ring-1 ring-black/5 transition-transform data-[state=checked]:translate-x-[1.125rem] contrast:bg-black contrast:ring-white" />
    </SwitchPrimitive.Root>
  );
}

/**
 * A setting as a plain row: label (plus an optional line of help) and a switch on the right.
 * No frame around it; the label stays clickable and the help is announced as the description.
 */
export function SwitchRow({
  label,
  description,
  checked,
  onCheckedChange,
  disabled,
  className,
}: {
  label: React.ReactNode;
  description?: React.ReactNode;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  className?: string;
}) {
  const id = React.useId();
  return (
    <div className={cn("flex justify-between gap-4 py-2", description ? "items-start" : "items-center", className)}>
      <div className="grid gap-0.5">
        <label htmlFor={id} className={cn("text-sm font-semibold text-ink", disabled ? "cursor-not-allowed" : "cursor-pointer")}>
          {label}
        </label>
        {description ? (
          <p id={`${id}-desc`} className="text-sm text-ink-2">
            {description}
          </p>
        ) : null}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onCheckedChange} disabled={disabled} aria-describedby={description ? `${id}-desc` : undefined} />
    </div>
  );
}

export function Slider({ className, ...props }: React.ComponentProps<typeof SliderPrimitive.Root>) {
  const count = (props.value ?? props.defaultValue ?? [0]).length;
  return (
    <SliderPrimitive.Root className={cn("relative flex h-6 w-full touch-none items-center select-none", className)} {...props}>
      <SliderPrimitive.Track className="relative h-1.5 grow overflow-hidden rounded-full bg-surface-3">
        <SliderPrimitive.Range className="absolute h-full bg-accent" />
      </SliderPrimitive.Track>
      {Array.from({ length: count }).map((_, i) => (
        <SliderPrimitive.Thumb
          key={i}
          aria-label={props["aria-label"]}
          className="block size-5 rounded-full border-2 border-accent bg-surface shadow-sm transition-shadow hover:ring-4 hover:ring-accent/20 focus-visible:outline-3 focus-visible:outline-focus"
        />
      ))}
    </SliderPrimitive.Root>
  );
}

/** Large selectable cards (wizard options). */
export function RadioCards<T extends string>({
  value,
  onValueChange,
  options,
  className,
  columns = 3,
  name,
}: {
  value: T;
  onValueChange: (v: T) => void;
  options: { value: T; title: string; description?: React.ReactNode; icon?: React.ReactNode; disabled?: boolean }[];
  className?: string;
  columns?: 1 | 2 | 3 | 4;
  name?: string;
}) {
  return (
    <RadioGroup.Root
      value={value}
      name={name}
      onValueChange={(v) => onValueChange(v as T)}
      className={cn(
        "grid gap-3",
        columns === 1 ? "grid-cols-1" : columns === 2 ? "sm:grid-cols-2" : columns === 3 ? "sm:grid-cols-2 lg:grid-cols-3" : "sm:grid-cols-2 lg:grid-cols-4",
        className,
      )}
    >
      {options.map((o) => (
        <RadioGroup.Item
          key={o.value}
          value={o.value}
          disabled={o.disabled}
          className="group relative flex gap-3 rounded-lg border border-line-strong bg-surface p-4 text-left transition-colors hover:border-ink-3 disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-accent data-[state=checked]:bg-accent/[0.06] data-[state=checked]:ring-1 data-[state=checked]:ring-accent contrast:data-[state=checked]:bg-transparent"
        >
          {o.icon ? <span className="mt-0.5 text-ink-2 group-data-[state=checked]:text-link [&_svg]:size-5">{o.icon}</span> : null}
          <span className="grid gap-1">
            <span className="text-sm font-semibold text-ink">{o.title}</span>
            {o.description ? <span className="text-sm leading-snug text-ink-2">{o.description}</span> : null}
          </span>
          <span className="absolute top-3 right-3 grid size-4 place-items-center rounded-full border border-line-strong group-data-[state=checked]:border-accent">
            <RadioGroup.Indicator className="size-2 rounded-full bg-accent" />
          </span>
        </RadioGroup.Item>
      ))}
    </RadioGroup.Root>
  );
}

/** Segmented control for small option sets (filters, toggles). */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  className,
  size = "md",
  "aria-label": ariaLabel,
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode }[];
  className?: string;
  size?: "sm" | "md";
  "aria-label"?: string;
}) {
  return (
    // min-height, not a fixed height: on a narrow screen a long option wraps inside its pill instead of spilling out,
    // and with very large text (A++ on a phone) whole options move to a second row.
    <div role="radiogroup" aria-label={ariaLabel} className={cn("inline-flex max-w-full flex-wrap rounded-lg border border-line-strong bg-surface-2 p-0.5", className)}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          onClick={() => onChange(o.value)}
          className={cn(
            "min-w-0 rounded-[4px] text-center leading-tight font-semibold text-ink-2 transition-colors hover:text-ink aria-checked:bg-surface aria-checked:text-ink aria-checked:shadow-sm aria-checked:ring-1 aria-checked:ring-line-strong contrast:aria-checked:ring-accent",
            size === "sm" ? "min-h-7 px-2.5 py-1 text-sm" : "min-h-8 px-3 py-1 text-sm",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
