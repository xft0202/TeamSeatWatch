import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCards, canDownload, createPublicRequests } from '../src/public/redeemState.ts';
import { publicApi, publicErrorMessage } from '../src/public/api.ts';

test('bulk cards preserve distinct original orders and never make client credential packages', () => {
  assert.deepEqual(parseCards('a\na，b b'), ['a', 'b']);
  assert.equal(canDownload({ hasOrder: true, canAccess: true, deliveryStatus: 'available', deliveryFormat: 'zip' }), true);
  for (const state of [{ canAccess: false, deliveryFormat: 'zip', deliveryStatus: 'available' }, { canAccess: true, deliveryFormat: 'legacy_json', deliveryStatus: 'available' }, { canAccess: true, deliveryFormat: 'zip', deliveryStatus: 'unavailable' }]) assert.equal(canDownload(state), false);
});
test('selection and response loss keep every authorization chain serial', () => {
  const requests = createPublicRequests();
  const claim = requests.begin();
  assert.equal(requests.begin(), null);
  assert.equal(requests.current(claim), true);
  requests.invalidate();
  const other = requests.begin();
  assert.equal(requests.current(claim), false);
  assert.equal(requests.finish(claim), false);
  assert.equal(requests.current(other), true);
  assert.equal(requests.finish(other), true);
});
test('Public transport requests the one original ZIP and handles denied/nonZIP/failed stream', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, options });
    return new Response(new Uint8Array([80, 75, 3, 4]), { headers: { 'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="Apophis-TeamSeatWatch-2026-10-03-00-00-00.zip"' } });
  };
  try {
    const file = await publicApi.download();
    assert.equal(file.filename, 'Apophis-TeamSeatWatch-2026-10-03-00-00-00.zip');
    assert.equal(file.blob.size, 4);
    assert.deepEqual(calls[0].options, { method: 'POST', credentials: 'include', headers: { Accept: 'application/zip' } });
    globalThis.fetch = async () => new Response('{}', { headers: { 'Content-Type': 'application/json' } });
    await assert.rejects(publicApi.download(), { message: 'public_delivery_pending' });
    globalThis.fetch = async () => new Response(JSON.stringify({ code: 'public_request_denied' }), { status: 404 });
    await assert.rejects(publicApi.download(), { message: 'public_request_denied' });
    globalThis.fetch = async () => { throw new Error('lost stream'); };
    await assert.rejects(publicApi.download(), { message: 'lost stream' });
    assert.equal(publicErrorMessage(new Error('public_request_denied')), publicErrorMessage(new Error('public_request_invalid')));
  } finally { globalThis.fetch = originalFetch; }
});
