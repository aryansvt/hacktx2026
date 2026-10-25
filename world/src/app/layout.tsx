import type { Metadata } from "next";
import "@fontsource/pirata-one/latin-400.css";
import "@fontsource/eb-garamond/latin-400.css";
import "@fontsource/eb-garamond/latin-700.css";
import "@fontsource/inter/latin-400.css";
import "./globals.css";
export const metadata: Metadata = {
  title: "Breadcrumbs | every attacker leaves a trail",
  description:
    "Explore encounters at a research honeypot through a live 3D globe.",
};
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
