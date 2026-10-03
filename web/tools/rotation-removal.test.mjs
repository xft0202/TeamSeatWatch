import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { URL } from 'node:url';
import { removalSlotAction, removalSlotStatus, removalErrorMessage } from '../src/rebuild/owner/rotationRemovalState.ts';
import { rotationJoinActionLabel, rotationJoinCredentials, rotationJoinMembership, rotationJoinPhase, rotationJoinUsage } from '../src/rebuild/owner/rotationJoinState.ts';
import { createRotationJoinRequests } from '../src/rebuild/owner/rotationJoinRequests.ts';

function slot(state, more = {}) {
  return { id: 'slot', platformMemberId: 'frozen-member', originalAccountId: 'original', candidateAccountId: 'frozen-candidate', identifier: 'original@example.test', seatType: 'prolite', state, attemptCount: 0, leaseEpoch: 0, uncertainObligation: false, lastErrorCode: '', updatedAt: '2026-01-01T00:00:00Z', candidateReady: false, ...more };
}
const progress = { previewId: 'original-preview', workspaceId: 'selected-space', workspaceName: 'selected', createdAt: '2026-01-01T00:00:00Z', authorizationDigest: 'a'.repeat(64), stopped: false, writeAllowed: true, slots: [] };

test('all eight persisted states have unambiguous owner-facing labels; only committed readiness says empty', () => {
  for (const state of ['pending', 'lease_acquired', 'remove_requested', 'remote_result_uncertain', 'absent_verification_pending', 'absent_verified', 'blocked', 'stopped']) {
    assert.equal(typeof removalSlotStatus(slot(state)), 'string');
    assert.notEqual(removalSlotStatus(slot(state)), state);
    if (state !== 'absent_verified') assert.doesNotMatch(removalSlotStatus(slot(state)), /空位已核实/);
  }
  assert.equal(removalSlotStatus(slot('absent_verified')), '空位证据待更新');
  assert.equal(removalSlotStatus(slot('absent_verified', { candidateReady: true })), '空位已核实');
});
test('no receipt, timeout, restart or different UI state can cause a second DELETE', () => {
  for (const state of ['remove_requested', 'remote_result_uncertain', 'absent_verification_pending', 'blocked', 'stopped', 'absent_verified']) {
    assert.equal(removalSlotAction(progress, slot(state, { remoteRequestId: 'original-request' }), 0), 'verify');
  }
  assert.equal(removalSlotAction(progress, slot('pending'), 0), 'run');
  assert.equal(removalSlotAction(progress, slot('blocked'), 0), 'run');
});
test('stop, authorization drift and live leases prevent new dispatch but preserve read-only reconciliation', () => {
  for (const removal of [{ ...progress, stopped: true }, { ...progress, writeAllowed: false }]) {
    assert.equal(removalSlotAction(removal, slot('pending'), 0), null);
    assert.equal(removalSlotAction(removal, slot('stopped', { remoteRequestId: 'original-request' }), 0), 'verify');
  }
  const leased = slot('lease_acquired', { leaseExpiresAt: '2026-01-01T00:01:00Z' });
  assert.equal(removalSlotAction(progress, leased, Date.parse('2026-01-01T00:00:00Z')), null);
  assert.equal(removalSlotAction(progress, leased, Date.parse('2026-01-01T00:02:00Z')), 'run');
});
test('browser mount, refresh and history recovery use only reads; stopped work is not silently recreated', () => {
  const ui = readFileSync(new URL('../src/rebuild/owner/RotationRemovalPanel.tsx', import.meta.url), 'utf8');
  const effects = ui.slice(ui.indexOf('  useEffect('), ui.indexOf('  async function control'));
  assert.doesNotMatch(effects, /rotationRemovalApi\.(start|run|stop|verify)\(/);
  assert.match(ui, /rotationRemovalApi\.history/);
  assert.match(ui, /expiryRotationApi\.get\(id\)/);
  assert.match(ui, /rotationRemovalApi\.get\(id\)/);
  assert.match(ui, /停止后续清退/);
  assert.match(ui, /只读核实原槽/);
  assert.doesNotMatch(ui, /Drawer|<input|<button|<select|重新执行整批/);
  assert.match(ui, /slot\.candidateReady \? '空位已核实，候选加入尚未启用' : '不可加入'/);
});
test('removal panel uses short business states and actions rather than teaching paragraphs', () => {
  const ui = readFileSync(new URL('../src/rebuild/owner/RotationRemovalPanel.tsx', import.meta.url), 'utf8');
  assert.match(ui, /停止后续清退/);
  assert.match(ui, /只读核实原槽/);
  assert.doesNotMatch(ui, /回执不算空位|停止或撤权不会撤回/);
});
test('request keys and target scope are stable after a lost response, reload or new login', () => {
  const client = readFileSync(new URL('../src/rebuild/owner/rotationRemoval.ts', import.meta.url), 'utf8');
  assert.match(client, /const digest = preview\.authorizationDigest/);
  assert.match(client, /if \(!digest\) throw/);
  assert.match(client, /authorizationDigest: digest/);
  assert.match(client, /idempotencyKey: preview\.id/);
  assert.doesNotMatch(client, /randomUUID|assignments:|platformMemberId:/);
  assert.match(client, /path: \{ previewId, slotId \}/);
  assert.doesNotMatch(client, /\.DELETE\(/);
});
test('join panel exposes explicit original-intent actions and saved usage qualification', () => {
  const ui = readFileSync(new URL('../src/rebuild/owner/RotationJoinPanel.tsx', import.meta.url), 'utf8');
  assert.match(ui, /rotationJoinApi\.get/);
  assert.match(ui, /rotationJoinApi\.act/);
  assert.match(ui, /status.deliveryReady/);
  assert.match(ui, /rotationJoinUsage/);
  assert.equal(rotationJoinUsage({ usage: 'unobserved' }), '用量待核实');
  assert.equal(rotationJoinUsage({ usage: 'shared' }), '用量范围待核实');
  assert.equal(rotationJoinUsage({ usage: 'unknown' }), '用量不明');
  assert.equal(rotationJoinActionLabel('observe'), '核实首次用量');
  assert.equal(rotationJoinActionLabel('recheck'), '重新核实用量');
  assert.doesNotMatch(ui, /password|refreshToken|accessToken|idToken|cookie|nonce|ciphertext/);
  assert.match(ui, /isCurrentAction/);
  assert.match(ui, /isCurrentRead/);
  assert.equal(rotationJoinPhase({ phase: 'credentials_complete' }), '成员已核实，凭据已保存');
  assert.equal(rotationJoinMembership({ membership: 'confirmed' }), '成员已确认');
  assert.equal(rotationJoinCredentials({ credentials: 'review_required' }), '需要人工复核');
  assert.equal(rotationJoinActionLabel('repair'), '按原尝试修复');
});
test('conflicts and transport errors do not claim completion or expose secret/technical response bodies', () => {
  assert.match(removalErrorMessage(409), /不要重建目标或重发清退/);
  assert.match(removalErrorMessage(401), /重新登录/);
  assert.match(removalErrorMessage(500), /仍按占用或待核验保留/);
});

function deferredJoin() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
function joinInteractions() {
  const requests = createRotationJoinRequests();
  const state = { status: null, error: '', busy: new Set(), posts: 0, reads: 0 };
  async function read(response) {
    const token = requests.beginRead();
    if (!token) return;
    state.reads++;
    try {
      const value = await response;
      if (requests.isCurrentRead(token)) { state.status = value; state.error = ''; }
    } catch {
      if (requests.isCurrentRead(token)) state.error = 'read failed';
    }
  }
  async function act(slot, response, reloadResponse) {
    const token = requests.beginAction(slot);
    if (!token) return;
    state.posts++; state.busy.add(slot); state.error = '';
    try {
      const value = await response;
      if (requests.isCurrentAction(token)) state.status = value;
    } catch {
      if (requests.isCurrentAction(token)) state.error = 'action failed';
    } finally {
      if (requests.finishAction(token)) { state.busy.delete(slot); await read(reloadResponse); }
    }
  }
  function changeScope() {
    requests.invalidate(); state.status = null; state.error = ''; state.busy.clear();
  }
  return { state, read, act, changeScope };
}

test('join async mount/reload is passive; a poll started before an action cannot overwrite it', async () => {
  const ui = joinInteractions(), oldPoll = deferredJoin(), post = deferredJoin();
  const pendingRead = ui.read(oldPoll.promise);
  const pendingAction = ui.act('slot', post.promise, Promise.resolve('complete'));
  await ui.act('slot', Promise.resolve('duplicate'), Promise.resolve('duplicate'));
  assert.equal(ui.state.posts, 1, 'synchronous double-click guard');
  await ui.read(Promise.resolve('stale while busy'));
  oldPoll.resolve('missing'); await pendingRead;
  assert.equal(ui.state.status, null, 'old poll invalidated at action start');
  post.resolve('complete'); await pendingAction;
  assert.equal(ui.state.status, 'complete'); assert.equal(ui.state.busy.size, 0);
  assert.equal(ui.state.reads, 2); assert.equal(ui.state.posts, 1);
});

test('join preview/slot switch fences old action response, error, finally and reload even after returning to same scope', async () => {
  for (const failure of [false, true]) {
    const ui = joinInteractions(), old = deferredJoin(), current = deferredJoin();
    const a = ui.act('slot', old.promise, Promise.resolve('old reload'));
    ui.changeScope(); ui.changeScope(); // A -> B -> A is still a new generation
    const b = ui.act('slot', current.promise, Promise.resolve('current complete'));
    if (failure) old.reject(new Error('old error')); else old.resolve('old complete');
    await a;
    assert.equal(ui.state.status, null); assert.equal(ui.state.error, '');
    assert.equal(ui.state.busy.has('slot'), true, 'old finally cannot release current guard');
    assert.equal(ui.state.reads, 0, 'old finally cannot read old preview');
    current.resolve('current complete'); await b;
    assert.equal(ui.state.status, 'current complete'); assert.equal(ui.state.busy.size, 0);
    assert.equal(ui.state.posts, 2); assert.equal(ui.state.reads, 1);
  }
});

test('join latest read fences both old status and old errors on slot scope changes', async () => {
  const ui = joinInteractions(), old = deferredJoin(), newer = deferredJoin();
  const a = ui.read(old.promise); const b = ui.read(newer.promise);
  newer.resolve('partial'); await b; old.reject(new Error('old')); await a;
  assert.equal(ui.state.status, 'partial'); assert.equal(ui.state.error, '');
  const previous = deferredJoin(), c = ui.read(previous.promise);
  ui.changeScope(); await ui.read(Promise.resolve('new slot'));
  previous.resolve('old slot'); await c;
  assert.equal(ui.state.status, 'new slot'); assert.equal(ui.state.posts, 0);
});
