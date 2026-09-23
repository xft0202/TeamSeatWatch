import type { components, paths } from '../generated/public';
import createClient from 'openapi-fetch';

export const publicApi = createClient<paths>({
  baseUrl: '',
  credentials: 'include',
});

type CardRequest = components['schemas']['CardRequest'];

function publicError(error: unknown) {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === 'string') return new Error(code);
  }
  return new Error('public_request_failed');
}

export async function confirmRedeem(cardSecret: string) {
  const response = await publicApi.POST('/api/public/v1/redeem/confirm', { body: { cardSecret } satisfies CardRequest });
  if (response.error || !response.data) throw publicError(response.error);
  return response.data;
}

export async function checkCredentialStatus(cardSecret: string) {
  const response = await publicApi.POST('/api/public/v1/redeem/credential-status', { body: { cardSecret } satisfies CardRequest });
  if (response.error || !response.data) throw publicError(response.error);
  return response.data;
}

export async function downloadDelivery(): Promise<Blob> {
  const response = await fetch('/api/public/v1/redeem/download', {
    method: 'POST',
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    let error: unknown;
    try { error = await response.json(); } catch { /* use stable fallback */ }
    throw publicError(error);
  }
  return response.blob();
}
