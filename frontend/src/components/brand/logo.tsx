import { cn } from "@/lib/utils";

/** Product mark: a hexagonal perimeter with a scanning arc ("C" for CBI). */
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden className={cn("size-8", className)}>
      <path
        d="M16 2.6 27.6 9.3v13.4L16 29.4 4.4 22.7V9.3Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path d="M21.7 11.3a7.2 7.2 0 1 0 0 9.4" fill="none" stroke="var(--accent)" strokeWidth="2.6" strokeLinecap="round" />
      <circle cx="16" cy="16" r="2.1" fill="var(--accent)" />
    </svg>
  );
}

export function Wordmark({ className, compact }: { className?: string; compact?: boolean }) {
  return (
    <span className={cn("flex items-center gap-2.5", className)}>
      <LogoMark className="text-chrome-ink" />
      <span className="flex items-baseline gap-2.5 leading-none">
        <span className="text-[1.0625rem] font-extrabold tracking-tight text-chrome-ink max-[359px]:sr-only">CBI AGH</span>
        {!compact ? (
          <span className="hidden border-l border-chrome-line pl-2.5 text-sm font-semibold text-chrome-ink-2 sm:inline">
            Attack Surface Intelligence
          </span>
        ) : null}
      </span>
    </span>
  );
}
