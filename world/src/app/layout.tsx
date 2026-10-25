import type { Metadata } from "next";
import "@fontsource/pirata-one/latin-400.css";
import "@fontsource/eb-garamond/latin-400.css";
import "@fontsource/eb-garamond/latin-400-italic.css";
import "@fontsource/eb-garamond/latin-700.css";
import "@fontsource/inter/latin-400.css";
import "@fontsource/jetbrains-mono/latin-400.css";
// extended subsets so polish, vietnamese and other accented city and guest names render
import "@fontsource/pirata-one/latin-ext-400.css";
import "@fontsource/eb-garamond/latin-ext-400.css";
import "@fontsource/eb-garamond/latin-ext-700.css";
import "@fontsource/eb-garamond/latin-ext-400-italic.css";
import "@fontsource/eb-garamond/vietnamese-400.css";
import "@fontsource/eb-garamond/vietnamese-700.css";
import "@fontsource/eb-garamond/vietnamese-400-italic.css";
import "@fontsource/inter/latin-ext-400.css";
import "@fontsource/inter/vietnamese-400.css";
import "./globals.css";
export const metadata: Metadata = {
  title: "Breadcrumbs | every attacker leaves a trail",
  description:
    "A live 3D globe of real attacks on a research honeypot, told as an illuminated chronicle.",
};
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
