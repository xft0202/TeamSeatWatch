import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { channelCanReceive, channelDeliveryLabel, channelFinalLabel, channelReceptionLabel } from '../src/rebuild/owner/channelDeliveryState.ts';
import { createRotationJoinRequests } from '../src/rebuild/owner/rotationJoinRequests.ts';

test('reception is distinct from final customer delivery and unknown receipts stay actionable', () => {
  assert.equal(channelDeliveryLabel({ phase: 'received' }), '待交付回执');
  assert.equal(channelReceptionLabel('received'), '渠道已接收');
  assert.equal(channelFinalLabel('pending'), '待交付回执');
  assert.equal(channelFinalLabel('delivered'), '已交付');
  assert.equal(channelReceptionLabel('record_pending'), '接收记录待处理');
  assert.equal(channelFinalLabel('record_pending'), '交付记录待处理');
  const ready = { packageId: 'original', nextAction: 'receive' };
  assert.equal(channelCanReceive(ready, true, false), true);
  assert.equal(channelCanReceive(ready, false, false), false);
  assert.equal(channelCanReceive(ready, true, true), false);
  assert.equal(channelCanReceive({ ...ready, nextAction: 'reconcile' }, true, false), false);
});
test('late polling and changed workspace cannot replace an original channel action result', () => {
  const requests = createRotationJoinRequests();
  const read = requests.beginRead();
  const action = requests.beginAction('channel');
  assert.equal(requests.isCurrentRead(read), false);
  assert.equal(requests.beginAction('channel'), null);
  assert.equal(requests.beginRead(), null);
  requests.invalidate();
  assert.equal(requests.isCurrentAction(action), false);
  assert.equal(requests.finishAction(action), false);
});
test('Mantine channel results remain in original operation and passive reload never pushes', () => {
  const ui = readFileSync(new URL('../src/rebuild/owner/ChannelDeliveryPanel.tsx', import.meta.url), 'utf8');
  const api = readFileSync(new URL('../src/rebuild/owner/channelDelivery.ts', import.meta.url), 'utf8');
  const parent = readFileSync(new URL('../src/rebuild/owner/RotationJoinPanel.tsx', import.meta.url), 'utf8');
  const effects = ui.slice(ui.indexOf('  useEffect('), ui.indexOf('  async function act'));
  assert.doesNotMatch(effects, /receive|reconcile/);
  assert.match(ui, /isCurrentRead/);
  assert.match(ui, /isCurrentAction/);
  assert.match(ui, /核验原回执/);
  assert.match(ui, /Table\.Th>渠道接收/);
  assert.match(ui, /Table\.Th>客户交付/);
  assert.match(ui, /key=\{`\$\{removal.previewId\}:\$\{removal.workspaceId\}`\}/);
  assert.match(api, /mutationHeaders/);
  assert.match(api, /confirmed: true/);
  assert.match(parent, /<BatchZIPPanel removal=\{removal\}/);
  assert.match(parent, /<ChannelDeliveryPanel removal=\{removal\}/);
  assert.doesNotMatch(ui, /Drawer|<input|<button|<a\s|OAuth|password|lease|sealed/);
});
