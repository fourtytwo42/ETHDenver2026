'use client';

import { useEffect, useMemo, useState } from 'react';

export type ChainKey = 'base_sepolia' | 'hardhat_local';

export const CHAIN_OPTIONS: Array<{ key: ChainKey; label: string }> = [
  { key: 'base_sepolia', label: 'Base Sepolia' },
  { key: 'hardhat_local', label: 'Hardhat Local' }
];

const STORAGE_KEY = 'xclaw_chain_key';
const EVENT_NAME = 'xclaw:chain_changed';

function isChainKey(value: unknown): value is ChainKey {
  return value === 'base_sepolia' || value === 'hardhat_local';
}

export function getStoredChainKey(): ChainKey {
  if (typeof window === 'undefined') {
    return 'base_sepolia';
  }
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (isChainKey(raw)) {
      return raw;
    }
  } catch {
    // ignore
  }
  return 'base_sepolia';
}

export function setStoredChainKey(chainKey: ChainKey): void {
  if (typeof window === 'undefined') {
    return;
  }
  window.localStorage.setItem(STORAGE_KEY, chainKey);
  window.dispatchEvent(new CustomEvent(EVENT_NAME, { detail: { chainKey } }));
}

export function useActiveChainKey(): [ChainKey, (next: ChainKey) => void, string] {
  const [chainKey, setChainKey] = useState<ChainKey>(() => getStoredChainKey());

  useEffect(() => {
    const onEvent = (event: Event) => {
      const custom = event as CustomEvent<{ chainKey?: unknown }>;
      const next = custom?.detail?.chainKey;
      if (isChainKey(next)) {
        setChainKey(next);
      }
    };

    const onStorage = (event: StorageEvent) => {
      if (event.key !== STORAGE_KEY) {
        return;
      }
      if (isChainKey(event.newValue)) {
        setChainKey(event.newValue);
      }
    };

    window.addEventListener(EVENT_NAME, onEvent);
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener(EVENT_NAME, onEvent);
      window.removeEventListener('storage', onStorage);
    };
  }, []);

  const set = (next: ChainKey) => {
    setChainKey(next);
    setStoredChainKey(next);
  };

  const label = useMemo(() => CHAIN_OPTIONS.find((opt) => opt.key === chainKey)?.label ?? chainKey, [chainKey]);

  return [chainKey, set, label];
}
