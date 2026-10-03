import createClient from 'openapi-fetch';
import type { components, paths } from '../../generated/owner';
import { mutationHeaders, OwnerApiError } from './auth';
const api = createClient<paths>({ baseUrl: '', credentials: 'include' });
export type PublicInventory = components['schemas']['PublicZIPInventory'];
export type PublicInventoryActivation = components['schemas']['ActivatePublicZIPInventoryRequest'];
function result<T>(response: { data?: T; error?: unknown; response: Response }): T {
  if (response.error || response.data === undefined) throw new OwnerApiError(response.response.status, response.error);
  return response.data;
}
export const publicInventoryApi = {
  get: async (packageId: string) => result(await api.GET('/api/owner/v1/public-inventory/{packageId}', { params: { path: { packageId } } })),
  activate: async (packageId: string, body: PublicInventoryActivation) => result(await api.POST('/api/owner/v1/public-inventory/{packageId}', { params: { path: { packageId }, header: await mutationHeaders() }, body })),
  revoke: async (packageId: string) => result(await api.POST('/api/owner/v1/public-inventory/{packageId}/revoke', { params: { path: { packageId }, header: await mutationHeaders() }, body: { confirmed: true } })),
};
export function generatePublicCard(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return `TSW1-${btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')}`;
}
