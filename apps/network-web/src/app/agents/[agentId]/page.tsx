'use client';

import { useEffect, useState } from 'react';
import { useParams, useRouter, useSearchParams } from 'next/navigation';

type BootstrapState =
  | { phase: 'idle' }
  | { phase: 'bootstrapping' }
  | { phase: 'error'; message: string }
  | { phase: 'ready' };

async function bootstrapSession(agentId: string, token: string): Promise<{ ok: true } | { ok: false; message: string }> {
  const response = await fetch('/api/v1/management/session/bootstrap', {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    credentials: 'same-origin',
    body: JSON.stringify({ agentId, token })
  });

  if (!response.ok) {
    let message = 'Bootstrap failed. Verify token and retry.';
    try {
      const payload = (await response.json()) as { message?: string };
      if (payload?.message) {
        message = payload.message;
      }
    } catch {
      // keep fallback message
    }
    return { ok: false, message };
  }

  return { ok: true };
}

export default function AgentManagementBootstrapPage() {
  const params = useParams<{ agentId: string }>();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [state, setState] = useState<BootstrapState>({ phase: 'idle' });
  const agentId = params.agentId;

  useEffect(() => {
    if (!agentId) {
      return;
    }

    const token = searchParams.get('token');
    if (!token) {
      setState({ phase: 'ready' });
      return;
    }

    setState({ phase: 'bootstrapping' });
    void bootstrapSession(agentId, token).then((result) => {
      if (!result.ok) {
        setState({ phase: 'error', message: result.message });
        return;
      }

      router.replace(`/agents/${agentId}`);
      setState({ phase: 'ready' });
    });
  }, [agentId, router, searchParams]);

  if (state.phase === 'bootstrapping') {
    return <main style={{ padding: '2rem' }}>Validating management token...</main>;
  }

  if (state.phase === 'error') {
    return (
      <main style={{ padding: '2rem' }}>
        <h1>Management bootstrap failed</h1>
        <p>{state.message}</p>
      </main>
    );
  }

  return (
    <main style={{ padding: '2rem' }}>
      <h1>Agent Management</h1>
      <p>Slice 08 bootstrap surface is active for this agent route.</p>
    </main>
  );
}
