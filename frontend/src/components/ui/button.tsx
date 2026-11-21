import { cva, type VariantProps } from "class-variance-authority";
import { Slot } from "radix-ui";
import * as React from "react";
import { cn } from "@/lib/utils";

export const buttonVariants = cva(
  "inline-flex shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-lg font-semibold transition-colors select-none disabled:cursor-not-allowed disabled:opacity-50 [&_svg]:size-4 [&_svg]:shrink-0",
  {
    variants: {
      variant: {
        primary: "bg-accent text-accent-ink hover:bg-accent-hover",
        secondary: "border border-line-strong bg-surface text-ink hover:bg-surface-2 hover:border-ink-3",
        ghost: "text-ink-2 hover:bg-surface-3 hover:text-ink",
        danger: "border border-danger/60 bg-surface text-danger hover:bg-danger-soft",
        chrome:
          "border border-chrome-line bg-chrome-raised text-chrome-ink hover:border-accent hover:text-white contrast:hover:text-accent",
        "chrome-ghost": "text-chrome-ink-2 hover:bg-chrome-raised hover:text-chrome-ink",
        link: "h-auto px-0 font-semibold text-link underline-offset-4 hover:underline",
      },
      size: {
        sm: "h-8 px-3 text-sm",
        md: "h-9 px-3.5 text-sm",
        lg: "h-11 px-5 text-base",
        icon: "size-9",
        "icon-sm": "size-8",
      },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild, type, ...props }, ref) => {
    const Comp = asChild ? Slot.Root : "button";
    return (
      <Comp
        ref={ref}
        // Marks link-buttons too (asChild), so the contrast theme doesn't underline them like text links.
        data-button=""
        type={asChild ? undefined : (type ?? "button")}
        className={cn(buttonVariants({ variant, size }), variant === "link" && "h-auto", className)}
        {...props}
      />
    );
  },
);
Button.displayName = "Button";
