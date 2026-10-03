import { Alert, Badge, Button, Group, Modal, Paper, ScrollArea, Stack, Table, Text, Title } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { channelDeliveryApi, type ChannelDeliveryStatus } from './channelDelivery';
import { channelCanReceive, channelDeliveryLabel, channelFinalLabel, channelReceptionLabel } from './channelDeliveryState';
import { createRotationJoinRequests } from './rotationJoinRequests';
import type { Removal } from './rotationRemoval';

export default function ChannelDeliveryPanel({ removal }: { removal: Removal }) {
  return <ScopedChannelDeliveryPanel key={`${removal.previewId}:${removal.workspaceId}`} removal={removal} />;
}
function ScopedChannelDeliveryPanel({ removal }: { removal: Removal }) {
  const [status, setStatus] = useState<ChannelDeliveryStatus>();
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState('');
  const requests = useRef(createRotationJoinRequests()).current;
  async function reload() {
    const token = requests.beginRead();
    if (!token) return;
    try {
      const next = await channelDeliveryApi.get(removal.previewId);
      if (requests.isCurrentRead(token)) { setStatus(next); setError(''); }
    } catch {
      if (requests.isCurrentRead(token)) setError('原渠道结果暂不可用');
    }
  }
  useEffect(() => {
    void reload();
    const timer = window.setInterval(() => void reload(), 3000);
    return () => { window.clearInterval(timer); requests.invalidate(); };
  }, []);
  async function act(action: 'receive' | 'reconcile') {
    const token = requests.beginAction('channel');
    if (!token) return;
    setBusy(true); setConfirm(false); setError('');
    try {
      const next = await channelDeliveryApi[action](removal.previewId);
      if (requests.isCurrentAction(token)) setStatus(next);
    } catch {
      if (requests.isCurrentAction(token)) setError('原交付待处理，请核验原回执');
    } finally {
      if (requests.finishAction(token)) { setBusy(false); void reload(); }
    }
  }
  const canReceive = channelCanReceive(status, removal.writeAllowed, removal.stopped);
  return <Paper withBorder p="md" aria-label="渠道交付结果"><Stack gap="sm">
    <Group justify="space-between"><Title order={3} size="h5">渠道交付</Title><Badge color={status?.phase === 'delivered' ? 'success' : 'warning'}>{channelDeliveryLabel(status)}</Badge></Group>
    <Group gap="md"><Text size="sm">{status?.destinationName ?? '本轮去向'}</Text><Text size="sm">已接收 {status?.receivedCount ?? 0}</Text><Text size="sm">已交付 {status?.deliveredCount ?? 0}</Text></Group>
    {error ? <Alert color="error" role="alert">{error}</Alert> : null}
    {status?.objects.length ? <ScrollArea h={280} type="auto"><Table striped highlightOnHover>
      <Table.Thead><Table.Tr><Table.Th>账号</Table.Th><Table.Th>渠道接收</Table.Th><Table.Th>客户交付</Table.Th></Table.Tr></Table.Thead>
      <Table.Tbody>{status.objects.map((object) => <Table.Tr key={object.accountId}><Table.Td>{object.identifier}</Table.Td><Table.Td>{channelReceptionLabel(object.reception)}</Table.Td><Table.Td>{channelFinalLabel(object.delivery)}</Table.Td></Table.Tr>)}</Table.Tbody>
    </Table></ScrollArea> : null}
    <Group>
      {canReceive ? <Button size="xs" disabled={busy} onClick={() => setConfirm(true)}>发送原对象</Button> : null}
      {status?.nextAction === 'reconcile' || status?.nextAction === 'receive' && status.objects.length > 0 ? <Button size="xs" variant="default" disabled={busy} loading={busy} onClick={() => void act('reconcile')}>核验原回执</Button> : null}
      <Button size="xs" variant="subtle" disabled={busy} onClick={() => void reload()}>刷新状态</Button>
    </Group>
    <Modal opened={confirm} onClose={() => setConfirm(false)} title="发送本轮对象" centered>
      <Stack><Text>{status?.destinationName ?? '本轮去向'} · {removal.slots.length} 个子号</Text><Group justify="flex-end"><Button variant="default" onClick={() => setConfirm(false)}>返回</Button><Button disabled={!canReceive || busy} onClick={() => void act('receive')}>确认发送</Button></Group></Stack>
    </Modal>
  </Stack></Paper>;
}
