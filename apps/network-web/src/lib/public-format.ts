export function formatUsd(value: string | number | null | undefined): string {
  if (value === null || value === undefined) {
    return '-';
  }

  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numeric)) {
    return '-';
  }

  const abs = Math.abs(numeric);
  const minimumFractionDigits = abs >= 1 ? 2 : 4;
  const maximumFractionDigits = abs >= 1 ? 2 : 4;

  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits,
    maximumFractionDigits
  }).format(numeric);
}

export function formatNumber(value: string | number | null | undefined): string {
  if (value === null || value === undefined) {
    return '-';
  }

  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numeric)) {
    return '-';
  }

  return new Intl.NumberFormat('en-US').format(numeric);
}

export function formatPercent(value: string | number | null | undefined): string {
  if (value === null || value === undefined) {
    return '-';
  }

  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numeric)) {
    return '-';
  }

  return `${numeric.toFixed(2)}%`;
}

export function formatUtc(iso: string | null | undefined): string {
  if (!iso) {
    return '-';
  }

  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return '-';
  }

  return date.toLocaleString('en-US', {
    timeZone: 'UTC',
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

export function isStale(iso: string | null | undefined, thresholdSeconds = 60): boolean {
  if (!iso) {
    return true;
  }

  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) {
    return true;
  }

  return Date.now() - ts > thresholdSeconds * 1000;
}

export function shortenAddress(address: string | null | undefined): string {
  if (!address) {
    return '-';
  }

  if (address.length < 12) {
    return address;
  }

  return `${address.slice(0, 6)}...${address.slice(-4)}`;
}
