import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { batchZIPCanGenerate, batchZIPDownloadURL, batchZIPLabel } from '../src/rebuild/owner/batchZIPState.ts';
import { createRotationJoinRequests } from '../src/rebuild/owner/rotationJoinRequests.ts';

test('prepared and reserved packages remain pending customer delivery', () => {
  assert.equal(batchZIPLabel({ phase: 'prepared' }), '待交付');
  assert.equal(batchZIPLabel({ phase: 'reserved' }), '待交付');
  assert.equal(batchZIPLabel({ phase: 'delivered' }), '已交付');
  assert.equal(batchZIPCanGenerate({ phase: 'pending', canGenerate: true, nextAction: 'generate' }), true);
  for (const phase of ['prepared', 'reserved', 'delivered']) assert.equal(batchZIPCanGenerate({ phase, canGenerate: true, nextAction: 'generate' }), false);
  assert.equal(batchZIPCanGenerate({ phase: 'pending', canGenerate: false, nextAction: 'generate' }), false);
});
test('lost response and changed workspace cannot make stale results overwrite original package', () => {
  const guard = createRotationJoinRequests();
  const poll = guard.beginRead();
  const action = guard.beginAction('batch');
  assert.equal(guard.isCurrentRead(poll), false);
  assert.equal(guard.beginAction('batch'), null);
  assert.equal(guard.beginRead(), null);
  guard.invalidate();
  assert.equal(guard.isCurrentAction(action), false);
  assert.equal(guard.finishAction(action), false);
  const current = guard.beginRead();
  assert.equal(guard.isCurrentRead(current), true);
});
test('one original ZIP is a result action; mounting and polling never generate it', () => {
  const ui = readFileSync(new URL('../src/rebuild/owner/BatchZIPPanel.tsx', import.meta.url), 'utf8');
  const client = readFileSync(new URL('../src/rebuild/owner/batchZIP.ts', import.meta.url), 'utf8');
  const effects = ui.slice(ui.indexOf('  useEffect('), ui.indexOf('  async function generate'));
  assert.doesNotMatch(effects, /batchZIPApi\.generate/);
  assert.match(ui, /key=\{`\$\{removal.previewId\}:\$\{removal.workspaceId\}`\}/);
  assert.match(ui, /isCurrentRead/);
  assert.match(ui, /isCurrentAction/);
  assert.match(ui, /下载原交付包/);
  assert.doesNotMatch(ui, /Drawer|<input|<button|<a\s|sub2api_all|split\/|OAuth|lease|password/);
  assert.match(client, /confirmed: true/);
  assert.match(client, /credentials: 'include'/);
  assert.match(client, /mutationHeaders/);
  assert.equal(batchZIPDownloadURL('original/id'), '/api/owner/v1/expiry-rotation/previews/original%2Fid/batch-zip/download');
  for (const page of ['ChildMaterialsView', 'StandbyChildBatchesView']) {
    const source = readFileSync(new URL(`../src/rebuild/owner/${page}.tsx`, import.meta.url), 'utf8');
    assert.doesNotMatch(source, /batchZIP|BatchZIP|sub2api/);
  }
});
