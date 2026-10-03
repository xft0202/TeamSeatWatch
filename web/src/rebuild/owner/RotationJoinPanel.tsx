import { Alert, Badge, Button, Group, Paper, Stack, Text } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { OwnerApiError } from './auth';
import { rotationJoinApi, type RotationJoinAction, type RotationJoinStatus } from './rotationJoin';
import { rotationJoinActionLabel, rotationJoinCredentials, rotationJoinErrorMessage, rotationJoinMembership, rotationJoinPhase, rotationJoinUsage } from './rotationJoinState';
import type { Removal, RemovalSlot } from './rotationRemoval';
import { createRotationJoinRequests } from './rotationJoinRequests';
import BatchZIPPanel from './BatchZIPPanel';
import ChannelDeliveryPanel from './ChannelDeliveryPanel';

export default function RotationJoinPanel({ removal }: { removal: Removal }) {
  const scope = `${removal.previewId}:${removal.workspaceId}:${removal.slots.map((slot) => slot.id).join('|')}`;
  return <ScopedRotationJoinPanel key={scope} removal={removal} />;
}

function ScopedRotationJoinPanel({ removal }: { removal: Removal }) {
  const [statuses, setStatuses] = useState<Record<string, RotationJoinStatus>>({});
  const [busy, setBusy] = useState(new Set<string>());
  const [error, setError] = useState('');
  const requests = useRef(createRotationJoinRequests()).current;

  async function reload() {
    const previewId = removal.previewId;
    const token = requests.beginRead();
    if (!token) return;
    try {
      const entries = await Promise.all(removal.slots.map(async (slot) => [slot.id, await rotationJoinApi.get(previewId, slot.id)] as const));
      if (!requests.isCurrentRead(token)) return;
      setStatuses(Object.fromEntries(entries));
      setError('');
    } catch (cause) {
      if (requests.isCurrentRead(token)) setError(rotationJoinErrorMessage(cause instanceof OwnerApiError ? cause.status : undefined));
    }
  }
  useEffect(() => {
    void reload();
    const timer = window.setInterval(() => void reload(), 3000);
    return () => { window.clearInterval(timer); requests.invalidate(); };
  }, []);

  async function act(slot: RemovalSlot, action: string) {
    if (!['run', 'verify', 'save', 'repair', 'observe', 'recheck'].includes(action)) return;
    // This synchronous guard also fences already in-flight polls before POST.
    const token = requests.beginAction(slot.id);
    if (!token) return;
    const typedAction = action as RotationJoinAction;
    const previewId = removal.previewId;
    setBusy((current) => new Set(current).add(slot.id));
    setError('');
    try {
      const status = await rotationJoinApi.act(previewId, slot.id, typedAction);
      if (requests.isCurrentAction(token)) setStatuses((current) => ({ ...current, [slot.id]: status }));
    } catch (cause) {
      if (requests.isCurrentAction(token)) setError(rotationJoinErrorMessage(cause instanceof OwnerApiError ? cause.status : undefined));
    } finally {
      if (requests.finishAction(token)) {
        setBusy((current) => { const next = new Set(current); next.delete(slot.id); return next; });
        void reload();
      }
    }
  }

  return <Paper withBorder p="md" aria-label="原候选加入与首次用量"><Stack gap="sm">
    <Group justify="space-between"><Text fw={600}>原候选加入与首次用量</Text><Button size="xs" variant="subtle" onClick={() => void reload()}>刷新状态</Button></Group>
    <Text size="xs" c="dimmed">{removal.workspaceName} · 原席位与目标空间</Text>
    {error ? <Alert color="red" role="alert">{error}</Alert> : null}
    {removal.slots.map((slot) => {
      const status = statuses[slot.id];
      if (!status) return <Text key={slot.id} size="sm" c="dimmed">{slot.identifier}：正在读取原义务状态…</Text>;
      const action = status.nextAction;
      const canAct = Boolean(action && action !== 'none' && removal.writeAllowed && !removal.stopped);
      return <Paper key={slot.id} withBorder p="sm" radius="sm"><Stack gap={4}>
        <Group justify="space-between"><Text size="sm" fw={500}>{status.candidateIdentifier || slot.identifier}</Text><Badge color={status.credentials === 'complete' ? 'green' : status.credentials === 'review_required' || status.credentials === 'unknown' ? 'yellow' : 'gray'}>{rotationJoinCredentials(status)}</Badge></Group>
        <Text size="xs">原席位：{slot.platformMemberId} · {rotationJoinPhase(status)} · 成员：{rotationJoinMembership(status)}</Text>
        {status.diagnostic !== 'none' ? <Text size="xs" c="dimmed">{status.diagnostic === 'action_in_progress' ? '原动作处理中' : status.diagnostic === 'original_authority_unavailable' ? '原授权当前不可用' : '等待核实'}</Text> : null}
        {status.credentials === 'complete' ? <Group gap="xs"><Badge color={status.deliveryReady ? 'green' : 'yellow'}>{rotationJoinUsage(status)}</Badge><Text size="xs">{status.deliveryReady ? '待交付' : '保留原席位'}</Text></Group> : null}
        {canAct ? <Button size="xs" variant="light" disabled={busy.has(slot.id)} loading={busy.has(slot.id)} onClick={() => void act(slot, action)}>{rotationJoinActionLabel(action)}</Button> : null}
      </Stack></Paper>;
    })}
    <BatchZIPPanel removal={removal} />
    <ChannelDeliveryPanel removal={removal} />
  </Stack></Paper>;
}
