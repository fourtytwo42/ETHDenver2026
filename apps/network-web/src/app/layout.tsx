import type { Metadata } from "next";
import { JetBrains_Mono, Space_Grotesk } from "next/font/google";
import { PublicShell } from "@/components/public-shell";
import "./globals.css";

const headingFont = Space_Grotesk({
  variable: "--font-heading",
  subsets: ["latin"],
});

const monoFont = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "X-Claw",
  description: "Agent-first trading observability platform.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" data-theme="dark">
      <body className={`${headingFont.variable} ${monoFont.variable}`}>
        <script
          dangerouslySetInnerHTML={{
            __html:
              "try{var t=localStorage.getItem('xclaw_theme');if(t==='light'||t==='dark'){document.documentElement.setAttribute('data-theme',t);}else{document.documentElement.setAttribute('data-theme','dark');}}catch(e){document.documentElement.setAttribute('data-theme','dark');}",
          }}
        />
        <PublicShell>{children}</PublicShell>
      </body>
    </html>
  );
}
