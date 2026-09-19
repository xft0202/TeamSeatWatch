import createClient from 'openapi-fetch';
import type { paths } from '../generated/owner';

// All Owner calls stay on the same origin and use the generated OpenAPI path map.
export const ownerApi = createClient<paths>({ baseUrl: '' });

let csrfToken = '';
let csrfRequest: Promise<string> | undefined;

/** Returns one shared CSRF bootstrap request so concurrent mutations use the same cookie/token pair. */
export async function ensureCsrf() {
  if (csrfToken) return csrfToken;
  if (!csrfRequest) {
    csrfRequest = (async () => {
      const response = await ownerApi.GET('/api/owner/v1/csrf');
      if (response.error || !response.data) {
        throw response.error ?? new Error('CSRF initialization failed');
      }
      csrfToken = response.data.token;
      return csrfToken;
    })().finally(() => {
      csrfRequest = undefined;
    });
  }
  return csrfRequest;
}

/** Supplies the required double-submit header for every Owner state change. */
export async function mutationHeaders() {
  return { 'X-CSRF-Token': await ensureCsrf() };
}

/** Drops tab-local CSRF state after logout or a server-side CSRF rejection. */
export function clearCsrf() {
  csrfToken = '';
  csrfRequest = undefined;
}
