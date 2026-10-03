import createClient from 'openapi-fetch';
import type { components, paths } from '../../generated/owner';
import { mutationHeaders, OwnerApiError } from './auth';

const api = createClient<paths>({ baseUrl: '', credentials: 'include' });
export type ChannelDeliveryStatus = components['schemas']['ChannelDeliveryStatus'];
function result<T>(response: { data?: T; error?: unknown; response: Response }): T {
  if (response.error || response.data === undefined) throw new OwnerApiError(response.response.status, response.error);
  return response.data;
}
export const channelDeliveryApi = {
  get: async (previewId: string) => result(await api.GET('/api/owner/v1/expiry-rotation/previews/{previewId}/channel-delivery', { params: { path: { previewId } } })),
  receive: async (previewId: string) => result(await api.POST('/api/owner/v1/expiry-rotation/previews/{previewId}/channel-delivery/receive', { params: { path: { previewId }, header: await mutationHeaders() }, body: { confirmed: true } })),
  reconcile: async (previewId: string) => result(await api.POST('/api/owner/v1/expiry-rotation/previews/{previewId}/channel-delivery/reconcile', { params: { path: { previewId }, header: await mutationHeaders() }, body: { confirmed: true } })),
};
