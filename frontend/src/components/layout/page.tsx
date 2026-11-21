import { ChevronLeft } from "lucide-react";
import Link from "next/link";
import * as React from "react";
import { cn } from "@/lib/utils";

export function Container({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("mx-auto w-full max-w-[1440px] px-4 sm:px-6 lg:px-8", className)} {...props} />;
}

export function PageHeader({
  title,
  description,
  actions,
  back,
  meta,
  className,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  back?: { href: string; label: string };
  meta?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-end justify-between gap-x-6 gap-y-4 pt-7 pb-6", className)}>
      <div className="grid min-w-0 max-w-3xl gap-1.5">
        {back ? (
          <Link href={back.href} className="inline-flex w-fit items-center gap-1 text-sm font-semibold text-link hover:underline">
            <ChevronLeft className="size-4" aria-hidden /> {back.label}
          </Link>
        ) : null}
        <h1 className="text-[1.75rem] leading-tight font-semibold tracking-[-0.015em] text-ink">{title}</h1>
        {description ? <p className="max-w-[65ch] text-sm leading-relaxed text-pretty text-ink-2">{description}</p> : null}
        {meta ? <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 pt-1 text-sm text-ink-2">{meta}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
