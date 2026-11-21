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
      <div className="grid min-w-0 max-w-3xl gap-2">
        {back ? (
          <Link href={back.href} className="inline-flex w-fit items-center gap-1 text-[0.8125rem] font-semibold text-link hover:underline">
            <ChevronLeft className="size-4" aria-hidden /> {back.label}
          </Link>
        ) : null}
        <h1 className="text-[1.75rem] leading-tight font-extrabold tracking-[-0.02em] text-ink">{title}</h1>
        {description ? <p className="text-[0.9375rem] leading-relaxed text-ink-2">{description}</p> : null}
        {meta ? <div className="flex flex-wrap items-center gap-2 pt-1">{meta}</div> : null}
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
