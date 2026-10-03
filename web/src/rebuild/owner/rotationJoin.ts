import createClient from 'openapi-fetch';
import type { components, paths } from '../../generated/owner';
import { mutationHeaders, OwnerApiError } from './auth';

const api = createClient<paths>({ baseUrl: '', credentials: 'include' });
export type RotationJoinStatus = components['schemas']['RotationJoinStatus'];
function result<T>(response: { data?: T; error?: unknown; response: Response }): T {
  if (response.error || response.data === undefined) throw new OwnerApiError(response.response.status, response.error);
  return response.data;
}
export type RotationJoinAction = 'run' | 'verify' | 'save' | 'repair' | 'observe' | 'recheck';
export const rotationJoinApi = {
  get: async (previewId: string, slotId: string) => result(await api.GET('/api/owner/v1/expiry-rotation/previews/{previewId}/removal/slots/{slotId}/join', { params: { path: { previewId, slotId } } })),
  act: async (previewId: string, slotId: string, action: RotationJoinAction) => {
    const paths = {
      run: '/api/owner/v1/expiry-rotation/previews/{previewId}/removal/slots/{slotId}/join/run',
      verify: '/api/owner/v1/expiry-rotation/previews/{previewId}/removal/slots/{slotId}/join/verify',
      save: '/api/owner/v1/expiry-rotation/previews/{previewId}/removal/slots/{slotId}/join/save',
      repair: '/api/owner/v1/expiry-rotation/previews/{previewId}/removal/slots/{slotId}/join/repair',
      observe: '/api/owner/v1/expiry-rotation/previews/{previewId}/removal/slots/{slotId}/join/usage',
      recheck: '/api/owner/v1/expiry-rotation/previews/{previewId}/removal/slots/{slotId}/join/usage/recheck',
    } as const;
    const path = paths[action];
    if (action === 'run') return result(await api.POST(path, { params: { path: { previewId, slotId }, header: await mutationHeaders() }, body: { confirmed: true } }));
    if (action === 'verify') return result(await api.POST(path, { params: { path: { previewId, slotId }, header: await mutationHeaders() }, body: { confirmed: true } }));
    if (action === 'save') return result(await api.POST(path, { params: { path: { previewId, slotId }, header: await mutationHeaders() }, body: { confirmed: true } }));
    return result(await api.POST(path, { params: { path: { previewId, slotId }, header: await mutationHeaders() }, body: { confirmed: true } }));
  },
};
