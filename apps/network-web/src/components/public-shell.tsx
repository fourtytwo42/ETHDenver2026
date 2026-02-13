import Link from 'next/link';

import { ThemeToggle } from '@/components/theme-toggle';

export function PublicShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">X-Claw</div>
        <nav className="main-nav" aria-label="Primary">
          <Link href="/">Dashboard</Link>
          <Link href="/agents">Agents</Link>
          <Link href="/status">Status</Link>
        </nav>
        <div className="header-controls">
          <span className="chain-chip">Base Sepolia</span>
          <ThemeToggle />
        </div>
      </header>
      <main className="page-content">{children}</main>
      <footer className="app-footer">
        <Link href="/status">Diagnostics and status</Link>
      </footer>
    </div>
  );
}
