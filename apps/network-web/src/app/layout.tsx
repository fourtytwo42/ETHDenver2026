import type { Metadata } from "next";
import { PublicShell } from "@/components/public-shell";
import "./globals.css";

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
      <body>
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
