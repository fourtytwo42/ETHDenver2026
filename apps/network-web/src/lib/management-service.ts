import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import { requireManagementTokenEncKey } from '@/lib/env';
import { type ApiErrorCode } from '@/lib/errors';
import { makeId } from '@/lib/ids';
import { withTransaction } from '@/lib/db';

const TOKEN_CIPHERTEXT_PREFIX = 'v1';

type ServiceError = {
  status: number;
  code: ApiErrorCode;
  message: string;
  actionHint?: string;
  details?: unknown;
};

type ServiceResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: ServiceError };

export type BootstrapInput = {
  agentId: string;
  token: string;
  userAgent: string | null;
};

export type BootstrapOutput = {
  agentId: string;
  sessionId: string;
  managementCookieValue: string;
  csrfToken: string;
  expiresAt: string;
};

export type StepupChallengeInput = {
  agentId: string;
  issuedFor: 'withdraw' | 'approval_scope_change' | 'sensitive_action';
  managementSessionId: string | null;
  userAgent: string | null;
};

export type StepupChallengeOutput = {
  challengeId: string;
  code: string;
  expiresAt: string;
};

export type StepupVerifyInput = {
  agentId: string;
  code: string;
  managementSessionId: string;
  userAgent: string | null;
};

export type StepupVerifyOutput = {
  stepupSessionId: string;
  stepupCookieValue: string;
  expiresAt: string;
};

export type RevokeAllInput = {
  agentId: string;
  managementSessionId: string;
  userAgent: string | null;
};

export type RevokeAllOutput = {
  agentId: string;
  revokedStepupSessions: number;
  revokedManagementSessions: number;
  newManagementToken: string;
};

export type IssueOwnerManagementLinkInput = {
  agentId: string;
  ttlSeconds: number;
};

export type IssueOwnerManagementLinkOutput = {
  agentId: string;
  token: string;
  issuedAt: string;
  expiresAt: string;
};

function getManagementKey(): Buffer {
  const decoded = Buffer.from(requireManagementTokenEncKey(), 'base64');
  if (decoded.length !== 32) {
    throw new Error('XCLAW_MANAGEMENT_TOKEN_ENC_KEY must decode to 32 bytes');
  }
  return decoded;
}

function hmacHex(domain: string, value: string): string {
  const hmac = createHmac('sha256', getManagementKey());
  hmac.update(domain);
  hmac.update(':');
  hmac.update(value);
  return hmac.digest('hex');
}

function nowPlusSeconds(seconds: number): Date {
  return new Date(Date.now() + seconds * 1000);
}

function parseCiphertext(ciphertext: string): { iv: Buffer; tag: Buffer; payload: Buffer } | null {
  const parts = ciphertext.split(':');
  if (parts.length !== 4 || parts[0] !== TOKEN_CIPHERTEXT_PREFIX) {
    return null;
  }

  try {
    const iv = Buffer.from(parts[1], 'base64url');
    const tag = Buffer.from(parts[2], 'base64url');
    const payload = Buffer.from(parts[3], 'base64url');
    if (iv.length !== 12 || tag.length !== 16 || payload.length === 0) {
      return null;
    }
    return { iv, tag, payload };
  } catch {
    return null;
  }
}

export function fingerprintManagementToken(token: string): string {
  return hmacHex('management_token', token);
}

export function hashManagementCookieSecret(sessionId: string, secret: string): string {
  return hmacHex('management_cookie', `${sessionId}.${secret}`);
}

function hashStepupCode(agentId: string, code: string): string {
  return hmacHex('stepup_code', `${agentId}.${code}`);
}

function encryptToken(token: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', getManagementKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${TOKEN_CIPHERTEXT_PREFIX}:${iv.toString('base64url')}:${tag.toString('base64url')}:${ciphertext.toString('base64url')}`;
}

function decryptToken(ciphertext: string): string | null {
  const parsed = parseCiphertext(ciphertext);
  if (!parsed) {
    return null;
  }

  try {
    const decipher = createDecipheriv('aes-256-gcm', getManagementKey(), parsed.iv);
    decipher.setAuthTag(parsed.tag);
    const plaintext = Buffer.concat([decipher.update(parsed.payload), decipher.final()]);
    return plaintext.toString('utf8');
  } catch {
    return null;
  }
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return timingSafeEqual(leftBuffer, rightBuffer);
}

function randomBrowserLabel(index: number): string {
  return `browser-${String(index).padStart(3, '0')}`;
}

function generateOneTimeCode(): string {
  const raw = randomBytes(4).readUInt32BE(0);
  const code = raw % 100000000;
  return String(code).padStart(8, '0');
}

function generateOpaqueToken(): string {
  return randomBytes(32).toString('base64url');
}

function generateOwnerLinkToken(expiresAt: Date): string {
  return `ol1.${Math.floor(expiresAt.getTime() / 1000)}.${generateOpaqueToken()}`;
}

function parseOwnerLinkToken(token: string): { expiresAtSec: number } | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'ol1') {
    return null;
  }
  const expiresAtSec = Number.parseInt(parts[1] ?? '', 10);
  if (!Number.isFinite(expiresAtSec) || expiresAtSec <= 0) {
    return null;
  }
  return { expiresAtSec };
}

export async function bootstrapManagementSession(input: BootstrapInput): Promise<ServiceResult<BootstrapOutput>> {
  const fingerprint = fingerprintManagementToken(input.token);

  return withTransaction(async (client) => {
    const tokenResult = await client.query<{
      token_id: string;
      token_ciphertext: string;
    }>(
      `
      select token_id, token_ciphertext
      from management_tokens
      where agent_id = $1
        and status = 'active'
        and token_fingerprint = $2
      order by created_at desc
      limit 1
      for update
      `,
      [input.agentId, fingerprint]
    );

    if (tokenResult.rowCount === 0) {
      return {
        ok: false,
        error: {
          status: 401,
          code: 'auth_invalid' as const,
          message: 'Management bootstrap token is invalid.',
          actionHint: 'Use a currently active management token for this agent.'
        }
      };
    }

    const row = tokenResult.rows[0];
    const decrypted = decryptToken(row.token_ciphertext);
    if (!decrypted || !constantTimeEqual(decrypted, input.token)) {
      return {
        ok: false,
        error: {
          status: 401,
          code: 'auth_invalid' as const,
          message: 'Management bootstrap token is invalid.',
          actionHint: 'Regenerate a management token and retry bootstrap.'
        }
      };
    }

    const ownerToken = parseOwnerLinkToken(decrypted);
    if (ownerToken && ownerToken.expiresAtSec * 1000 <= Date.now()) {
      await client.query(
        `
        update management_tokens
        set status = 'rotated',
            rotated_at = now(),
            updated_at = now()
        where token_id = $1
        `,
        [row.token_id]
      );
      return {
        ok: false,
        error: {
          status: 401,
          code: 'auth_invalid' as const,
          message: 'Management bootstrap token has expired.',
          actionHint: 'Generate a fresh owner link token and retry immediately.'
        }
      };
    }

    await client.query(
      `
      update management_tokens
      set status = 'rotated',
          rotated_at = now(),
          updated_at = now()
      where token_id = $1
      `,
      [row.token_id]
    );

    const sessionCountResult = await client.query<{ total: string }>(
      'select count(*)::text as total from management_sessions where agent_id = $1',
      [input.agentId]
    );

    const sessionIndex = Number.parseInt(sessionCountResult.rows[0]?.total ?? '0', 10) + 1;
    const sessionId = makeId('msn');
    const sessionSecret = randomBytes(24).toString('base64url');
    const cookieHash = hashManagementCookieSecret(sessionId, sessionSecret);
    const expiresAt = nowPlusSeconds(30 * 24 * 60 * 60);

    await client.query(
      `
      insert into management_sessions (
        session_id, agent_id, label, cookie_hash, expires_at, created_at, updated_at
      ) values ($1, $2, $3, $4, $5, now(), now())
      `,
      [sessionId, input.agentId, randomBrowserLabel(sessionIndex), cookieHash, expiresAt.toISOString()]
    );

    await client.query(
      `
      insert into management_audit_log (
        audit_id,
        agent_id,
        management_session_id,
        action_type,
        action_status,
        public_redacted_payload,
        private_payload,
        user_agent,
        created_at
      ) values ($1, $2, $3, 'session.bootstrap', 'accepted', $4::jsonb, $5::jsonb, $6, now())
      `,
      [
        makeId('aud'),
        input.agentId,
        sessionId,
        JSON.stringify({ sessionLabel: randomBrowserLabel(sessionIndex) }),
        JSON.stringify({ tokenId: row.token_id }),
        input.userAgent
      ]
    );

    return {
      ok: true,
      data: {
        agentId: input.agentId,
        sessionId,
        managementCookieValue: `${sessionId}.${sessionSecret}`,
        csrfToken: randomBytes(24).toString('base64url'),
        expiresAt: expiresAt.toISOString()
      }
    };
  });
}

export async function issueOwnerManagementLink(input: IssueOwnerManagementLinkInput): Promise<ServiceResult<IssueOwnerManagementLinkOutput>> {
  const ttlSeconds = Math.min(Math.max(Math.trunc(input.ttlSeconds), 60), 3600);
  const issuedAt = new Date();
  const expiresAt = nowPlusSeconds(ttlSeconds);
  const token = generateOwnerLinkToken(expiresAt);
  const tokenCiphertext = encryptToken(token);
  const tokenFingerprint = fingerprintManagementToken(token);

  return withTransaction(async (client) => {
    const agent = await client.query<{ agent_id: string }>(
      `
      select agent_id
      from agents
      where agent_id = $1
      limit 1
      `,
      [input.agentId]
    );

    if (agent.rowCount === 0) {
      return {
        ok: false,
        error: {
          status: 401,
          code: 'auth_invalid' as const,
          message: 'Authenticated agent is not registered.',
          actionHint: 'Register agent before issuing owner management links.'
        }
      };
    }

    await client.query(
      `
      insert into management_tokens (
        token_id, agent_id, token_ciphertext, token_fingerprint, status, rotated_at, created_at, updated_at
      ) values ($1, $2, $3, $4, 'active', null, now(), now())
      `,
      [makeId('mtk'), input.agentId, tokenCiphertext, tokenFingerprint]
    );

    return {
      ok: true,
      data: {
        agentId: input.agentId,
        token,
        issuedAt: issuedAt.toISOString(),
        expiresAt: expiresAt.toISOString()
      }
    };
  });
}

export async function createStepupChallenge(input: StepupChallengeInput): Promise<ServiceResult<StepupChallengeOutput>> {
  return withTransaction(async (client) => {
    const challengeId = makeId('stc');
    const code = generateOneTimeCode();
    const codeHash = hashStepupCode(input.agentId, code);
    const expiresAt = nowPlusSeconds(24 * 60 * 60);

    await client.query(
      `
      insert into stepup_challenges (
        challenge_id, agent_id, code_hash, issued_for, expires_at, consumed_at, failed_attempts, created_at, updated_at
      ) values ($1, $2, $3, $4, $5, null, 0, now(), now())
      `,
      [challengeId, input.agentId, codeHash, input.issuedFor, expiresAt.toISOString()]
    );

    await client.query(
      `
      insert into management_audit_log (
        audit_id,
        agent_id,
        management_session_id,
        action_type,
        action_status,
        public_redacted_payload,
        private_payload,
        user_agent,
        created_at
      ) values ($1, $2, $3, 'stepup.challenge', 'accepted', $4::jsonb, $5::jsonb, $6, now())
      `,
      [
        makeId('aud'),
        input.agentId,
        input.managementSessionId,
        JSON.stringify({ issuedFor: input.issuedFor }),
        JSON.stringify({ challengeId }),
        input.userAgent
      ]
    );

    return {
      ok: true,
      data: {
        challengeId,
        code,
        expiresAt: expiresAt.toISOString()
      }
    };
  });
}

export async function verifyStepupChallenge(input: StepupVerifyInput): Promise<ServiceResult<StepupVerifyOutput>> {
  const codeHash = hashStepupCode(input.agentId, input.code);

  return withTransaction(async (client) => {
    const challenge = await client.query<{
      challenge_id: string;
      expires_at: string;
      consumed_at: string | null;
      failed_attempts: number;
    }>(
      `
      select challenge_id, expires_at::text, consumed_at::text, failed_attempts
      from stepup_challenges
      where agent_id = $1
        and code_hash = $2
      order by created_at desc
      limit 1
      `,
      [input.agentId, codeHash]
    );

    if (challenge.rowCount === 0) {
      await client.query(
        `
        update stepup_challenges
        set failed_attempts = failed_attempts + 1,
            updated_at = now()
        where challenge_id = (
          select challenge_id
          from stepup_challenges
          where agent_id = $1
            and consumed_at is null
            and expires_at > now()
          order by created_at desc
          limit 1
        )
        `,
        [input.agentId]
      );

      return {
        ok: false,
        error: {
          status: 401,
          code: 'stepup_invalid' as const,
          message: 'Step-up code is invalid.',
          actionHint: 'Request a new step-up challenge and verify with the latest code.'
        }
      };
    }

    const row = challenge.rows[0];
    if (row.consumed_at) {
      return {
        ok: false,
        error: {
          status: 401,
          code: 'stepup_invalid' as const,
          message: 'Step-up code has already been used.',
          actionHint: 'Request a new step-up challenge.'
        }
      };
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      return {
        ok: false,
        error: {
          status: 401,
          code: 'stepup_expired' as const,
          message: 'Step-up code has expired.',
          actionHint: 'Request a new step-up challenge and verify within 24 hours.'
        }
      };
    }

    await client.query(
      `
      update stepup_challenges
      set consumed_at = now(),
          updated_at = now()
      where challenge_id = $1
      `,
      [row.challenge_id]
    );

    const stepupSessionId = makeId('stu');
    const expiresAt = nowPlusSeconds(24 * 60 * 60);

    await client.query(
      `
      insert into stepup_sessions (
        stepup_session_id, agent_id, management_session_id, expires_at, revoked_at, created_at, updated_at
      ) values ($1, $2, $3, $4, null, now(), now())
      `,
      [stepupSessionId, input.agentId, input.managementSessionId, expiresAt.toISOString()]
    );

    await client.query(
      `
      insert into management_audit_log (
        audit_id,
        agent_id,
        management_session_id,
        action_type,
        action_status,
        public_redacted_payload,
        private_payload,
        user_agent,
        created_at
      ) values ($1, $2, $3, 'stepup.verify', 'accepted', $4::jsonb, $5::jsonb, $6, now())
      `,
      [
        makeId('aud'),
        input.agentId,
        input.managementSessionId,
        JSON.stringify({ expiresAt: expiresAt.toISOString() }),
        JSON.stringify({ challengeId: row.challenge_id, stepupSessionId }),
        input.userAgent
      ]
    );

    return {
      ok: true,
      data: {
        stepupSessionId,
        stepupCookieValue: stepupSessionId,
        expiresAt: expiresAt.toISOString()
      }
    };
  });
}

export async function revokeAllAndRotateManagementToken(input: RevokeAllInput): Promise<ServiceResult<RevokeAllOutput>> {
  const newToken = generateOpaqueToken();
  const newTokenCiphertext = encryptToken(newToken);
  const newTokenFingerprint = fingerprintManagementToken(newToken);

  return withTransaction(async (client) => {
    const activeToken = await client.query<{ token_id: string }>(
      `
      select token_id
      from management_tokens
      where agent_id = $1
        and status = 'active'
      order by created_at desc
      limit 1
      for update
      `,
      [input.agentId]
    );

    if (activeToken.rowCount === 0) {
      return {
        ok: false,
        error: {
          status: 401,
          code: 'auth_invalid' as const,
          message: 'No active management token exists for this agent.',
          actionHint: 'Bootstrap management access with a valid token before revocation.'
        }
      };
    }

    const revokedStepup = await client.query<{ stepup_session_id: string }>(
      `
      update stepup_sessions
      set revoked_at = now(),
          updated_at = now()
      where agent_id = $1
        and revoked_at is null
        and expires_at > now()
      returning stepup_session_id
      `,
      [input.agentId]
    );

    const revokedMgmt = await client.query<{ session_id: string }>(
      `
      update management_sessions
      set revoked_at = now(),
          updated_at = now()
      where agent_id = $1
        and revoked_at is null
        and expires_at > now()
      returning session_id
      `,
      [input.agentId]
    );

    await client.query(
      `
      update management_tokens
      set status = 'rotated',
          rotated_at = now(),
          updated_at = now()
      where agent_id = $1
        and status = 'active'
      `,
      [input.agentId]
    );

    const newTokenId = makeId('mtk');
    await client.query(
      `
      insert into management_tokens (
        token_id, agent_id, token_ciphertext, token_fingerprint, status, rotated_at, created_at, updated_at
      ) values ($1, $2, $3, $4, 'active', null, now(), now())
      `,
      [newTokenId, input.agentId, newTokenCiphertext, newTokenFingerprint]
    );

    await client.query(
      `
      insert into management_audit_log (
        audit_id,
        agent_id,
        management_session_id,
        action_type,
        action_status,
        public_redacted_payload,
        private_payload,
        user_agent,
        created_at
      ) values ($1, $2, $3, 'token.rotate', 'accepted', $4::jsonb, $5::jsonb, $6, now())
      `,
      [
        makeId('aud'),
        input.agentId,
        input.managementSessionId,
        JSON.stringify({
          revokedStepupSessions: revokedStepup.rowCount,
          revokedManagementSessions: revokedMgmt.rowCount
        }),
        JSON.stringify({ previousTokenId: activeToken.rows[0].token_id, newTokenId }),
        input.userAgent
      ]
    );

    return {
      ok: true,
      data: {
        agentId: input.agentId,
        revokedStepupSessions: revokedStepup.rowCount ?? 0,
        revokedManagementSessions: revokedMgmt.rowCount ?? 0,
        newManagementToken: newToken
      }
    };
  });
}

export function mintEncryptedManagementToken(token: string): { ciphertext: string; fingerprint: string } {
  return {
    ciphertext: encryptToken(token),
    fingerprint: fingerprintManagementToken(token)
  };
}
