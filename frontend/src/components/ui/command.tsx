"use client";

import { Command as CommandPrimitive } from "cmdk";
import { Search } from "lucide-react";
import * as React from "react";
import { cn } from "@/lib/utils";

export function Command({ className, ...props }: React.ComponentProps<typeof CommandPrimitive>) {
  return <CommandPrimitive className={cn("flex h-full w-full flex-col overflow-hidden bg-surface text-ink", className)} {...props} />;
}

export function CommandInput({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Input>) {
  return (
    <div className="flex items-center gap-2.5 border-b border-line px-4">
      <Search className="size-4 shrink-0 text-ink-2" aria-hidden />
      <CommandPrimitive.Input
        className={cn("h-13 w-full bg-transparent py-3 text-base outline-none placeholder:text-ink-3", className)}
        {...props}
      />
    </div>
  );
}

export function CommandList({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.List>) {
  return <CommandPrimitive.List className={cn("scroll-quiet max-h-[min(60vh,28rem)] overflow-y-auto p-2", className)} {...props} />;
}

export function CommandEmpty(props: React.ComponentProps<typeof CommandPrimitive.Empty>) {
  return <CommandPrimitive.Empty className="px-3 py-8 text-center text-sm text-ink-2" {...props} />;
}

export function CommandGroup({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Group>) {
  return (
    <CommandPrimitive.Group
      className={cn("[&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:pt-2 [&_[cmdk-group-heading]]:pb-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:text-ink-2", className)}
      {...props}
    />
  );
}

export function CommandItem({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Item>) {
  return (
    <CommandPrimitive.Item
      className={cn(
        "flex cursor-default items-center gap-3 rounded-lg px-2.5 py-2 text-sm outline-none select-none data-[selected=true]:bg-surface-3 [&_svg]:size-4 [&_svg]:shrink-0 [&_svg]:text-ink-2 contrast:data-[selected=true]:outline contrast:data-[selected=true]:outline-1 contrast:data-[selected=true]:outline-accent",
        className,
      )}
      {...props}
    />
  );
}
