import type { Metadata, Viewport } from "next";
import { Atkinson_Hyperlegible_Mono, Atkinson_Hyperlegible_Next } from "next/font/google";
import { Providers } from "@/components/providers";
import { PREFS_SCRIPT } from "@/lib/prefs";
import "./globals.css";

/* Atkinson Hyperlegible: designed for character disambiguation (0/O, 1/l/I) —
   it matters for IP addresses and hashes, and for public-sector accessibility. */
const sans = Atkinson_Hyperlegible_Next({ variable: "--font-ahn", subsets: ["latin", "latin-ext"], display: "swap", adjustFontFallback: false });
const mono = Atkinson_Hyperlegible_Mono({ variable: "--font-ahm", subsets: ["latin", "latin-ext"], display: "swap", adjustFontFallback: false });

export const metadata: Metadata = {
  title: { default: "Attack Surface Intelligence — CBI AGH", template: "%s — Attack Surface Intelligence" },
  description: "Ciągły monitoring i analiza zmian powierzchni ataku infrastruktury sieciowej (ponad 10 000 adresów IP).",
  applicationName: "Attack Surface Intelligence",
};

export const viewport: Viewport = {
  themeColor: "#000000",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  // "contrast" = DEFAULT_THEME in lib/prefs.tsx; PREFS_SCRIPT swaps in a theme the user picked.
  return (
    <html lang="pl" data-theme="contrast" suppressHydrationWarning className={`${sans.variable} ${mono.variable} antialiased`}>
      <head>
        <script dangerouslySetInnerHTML={{ __html: PREFS_SCRIPT }} />
      </head>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
