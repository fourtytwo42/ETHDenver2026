import type { PublicStatus } from '@/lib/public-types';

export function PublicStatusBadge({ status }: { status: PublicStatus }) {
  return <span className={`status-badge status-${status}`}>{status}</span>;
}
