export const PUBLIC_STATUSES = ['active', 'offline', 'degraded', 'paused', 'deactivated'] as const;
export type PublicStatus = (typeof PUBLIC_STATUSES)[number];

export const PUBLIC_MODES = ['mock', 'real', 'all'] as const;
export type PublicMode = (typeof PUBLIC_MODES)[number];

export function isPublicStatus(value: string): value is PublicStatus {
  return (PUBLIC_STATUSES as readonly string[]).includes(value);
}

export function isPublicMode(value: string): value is PublicMode {
  return (PUBLIC_MODES as readonly string[]).includes(value);
}
