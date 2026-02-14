import Link from 'next/link';

import { ManagementHeaderControls } from '@/components/management-header-controls';
import { ThemeToggle } from '@/components/theme-toggle';

export function PublicShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="header-left">
          <div className="brand">X-Claw</div>
          <nav className="main-nav" aria-label="Primary">
            <Link href="/">Dashboard</Link>
            <Link href="/agents">Agents</Link>
            <Link href="/status">Status</Link>
          </nav>
        </div>
        <div className="header-right">
          <div className="header-controls">
            <span className="chain-chip">Base Sepolia</span>
            <ManagementHeaderControls />
            <ThemeToggle />
          </div>
        </div>
      </header>
      <main className="page-content">{children}</main>
      <footer className="app-footer">
        <Link href="/status">Diagnostics and status</Link>
      </footer>
    </div>
  );
}
