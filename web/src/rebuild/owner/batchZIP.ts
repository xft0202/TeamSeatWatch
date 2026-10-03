import createClient from 'openapi-fetch';
import type { components, paths } from '../../generated/owner';
import { mutationHeaders, OwnerApiError } from './auth';

const api = createClient<paths>({ baseUrl: '', credentials: 'include' });
export type BatchZIPStatus = components['schemas']['BatchZIPStatus'];
function result<T>(response: { data?: T; error?: unknown; response: Response }): T {
  if (response.error || response.data === undefined) throw new OwnerApiError(response.response.status, response.error);
  return response.data;
}
export const batchZIPApi = {
  get: async (previewId: string) => result(await api.GET('/api/owner/v1/expiry-rotation/previews/{previewId}/batch-zip', { params: { path: { previewId } } })),
  generate: async (previewId: string) => result(await api.POST('/api/owner/v1/expiry-rotation/previews/{previewId}/batch-zip', { params: { path: { previewId }, header: await mutationHeaders() }, body: { confirmed: true } })),
};
