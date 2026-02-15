'use client';

import { useRouter } from 'next/navigation';

import { CHAIN_OPTIONS, type ChainKey, useActiveChainKey } from '@/lib/active-chain';

export function ChainHeaderControl() {
  const router = useRouter();
  const [chainKey, setChainKey] = useActiveChainKey();

  const onChange = (next: ChainKey) => {
    setChainKey(next);
    // Ensure any server components/data fetches keyed by chain revalidate.
    router.refresh();
  };

  return (
    <div className="chain-header-control">
      <label className="sr-only" htmlFor="chain-select">
        Network
      </label>
      <select id="chain-select" value={chainKey} onChange={(e) => onChange(e.target.value as ChainKey)} className="chain-select">
        {CHAIN_OPTIONS.map((opt) => (
          <option key={opt.key} value={opt.key}>
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  );
}
