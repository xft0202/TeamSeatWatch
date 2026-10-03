import { Alert, Badge, Button, Group, Paper, Stack, Text } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { batchZIPApi, type BatchZIPStatus } from './batchZIP';
import { batchZIPCanGenerate, batchZIPDownloadURL, batchZIPLabel } from './batchZIPState';
import { createRotationJoinRequests } from './rotationJoinRequests';
import type { Removal } from './rotationRemoval';
import PublicInventoryPanel from './PublicInventoryPanel';

export default function BatchZIPPanel({ removal }: { removal: Removal }) {
  return <ScopedBatchZIPPanel key={`${removal.previewId}:${removal.workspaceId}`} removal={removal} />;
}
function ScopedBatchZIPPanel({ removal }: { removal: Removal }) {
  const [status, setStatus] = useState<BatchZIPStatus>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const requests = useRef(createRotationJoinRequests()).current;
  async function reload() {
    const token = requests.beginRead();
    if (!token) return;
    try {
      const next = await batchZIPApi.get(removal.previewId);
      if (requests.isCurrentRead(token)) { setStatus(next); setError(''); }
    } catch {
      if (requests.isCurrentRead(token)) setError('原交付包状态暂不可用');
    }
  }
  useEffect(() => {
    void reload();
    const timer = window.setInterval(() => void reload(), 3000);
    return () => { window.clearInterval(timer); requests.invalidate(); };
  }, []);
  async function generate() {
    const token = requests.beginAction('batch');
    if (!token) return;
    setBusy(true); setError('');
    try {
      const next = await batchZIPApi.generate(removal.previewId);
      if (requests.isCurrentAction(token)) setStatus(next);
    } catch {
      if (requests.isCurrentAction(token)) setError('原批次待处理，请刷新状态');
    } finally {
      if (requests.finishAction(token)) { setBusy(false); void reload(); }
    }
  }
  return <Paper withBorder p="md" aria-label="批次交付结果"><Stack gap="sm">
    <Group justify="space-between"><Text fw={600}>批次交付包</Text><Badge color={status?.phase === 'delivered' ? 'green' : 'yellow'}>{batchZIPLabel(status)}</Badge></Group>
    <Text size="sm">{status?.accountCount ?? removal.slots.length} 个子号</Text>
    {error ? <Alert color="red" role="alert">{error}</Alert> : null}
    <Group>
      {batchZIPCanGenerate(status) && removal.writeAllowed && !removal.stopped ? <Button size="xs" onClick={() => void generate()} loading={busy} disabled={busy}>生成交付包</Button> : null}
      {status?.nextAction === 'download' && status.packageId ? <Button size="xs" component="a" href={batchZIPDownloadURL(removal.previewId)} download={status.filename}>下载原交付包</Button> : null}
      <Button size="xs" variant="subtle" disabled={busy} onClick={() => void reload()}>刷新状态</Button>
    </Group>
    {status?.packageId ? <PublicInventoryPanel key={status.packageId} packageId={status.packageId} /> : null}
  </Stack></Paper>;
}
