import type { PublicMode } from '@/lib/public-types';

export function ModeBadge({ mode }: { mode: Exclude<PublicMode, 'all'> }) {
  return <span className={`mode-badge mode-${mode}`}>{mode}</span>;
}
