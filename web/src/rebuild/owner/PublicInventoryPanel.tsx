import { Alert, Badge, Button, Checkbox, Group, Paper, Stack, Text, TextInput } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { createRotationJoinRequests } from './rotationJoinRequests';
import { generatePublicCard, publicInventoryApi, type PublicInventory } from './publicInventory';
export default function PublicInventoryPanel({ packageId }: { packageId: string }) {
  const [status, setStatus] = useState<PublicInventory>();
  const [card, setCard] = useState('');
  const [claimExpiry, setClaimExpiry] = useState('');
  const [accessExpiry, setAccessExpiry] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const requests = useRef(createRotationJoinRequests()).current;
  async function reload() {
    const token = requests.beginRead(); if (!token) return;
    try { const next = await publicInventoryApi.get(packageId); if (requests.isCurrentRead(token)) setStatus(next); }
    catch { if (requests.isCurrentRead(token)) setError('卡密库存状态暂不可用'); }
  }
  useEffect(() => { void reload(); return () => requests.invalidate(); }, []);
  async function save(revoke: boolean) {
    const token = requests.beginAction('public-inventory'); if (!token) return;
    setBusy(true); setError('');
    try {
      const next = revoke ? await publicInventoryApi.revoke(packageId) : await publicInventoryApi.activate(packageId, { cardSecret: card, claimExpiresAt: new Date(claimExpiry).toISOString(), accessExpiresAt: new Date(accessExpiry).toISOString(), confirmed: true });
      if (requests.isCurrentAction(token)) { setStatus(next); setConfirmed(false); }
    } catch { if (requests.isCurrentAction(token)) setError('授权操作未完成，请保留原卡密和期限后刷新状态'); }
    finally { if (requests.finishAction(token)) { setBusy(false); void reload(); } }
  }
  const active = status?.status === 'active';
  return <Paper withBorder radius={12} p="md" aria-label="Public 卡密库存"><Stack gap="sm">
    <Group justify="space-between"><Text fw={600}>卡密领取</Text><Badge color={active ? 'success' : 'gray'}>{status?.status === 'revoked' ? '已撤销' : active ? status?.hasOrder ? '已领取' : '已激活' : status?.status === 'unavailable' ? '授权不可用' : '未激活'}</Badge></Group>
    {error ? <Alert color="red" role="alert">{error}</Alert> : null}
    {status?.status === 'not_activated' ? <>
      <TextInput label="卡密" value={card} autoComplete="off" disabled={busy} onChange={(event) => setCard(event.currentTarget.value)} />
      <Button size="xs" variant="subtle" disabled={busy || !!card} onClick={() => setCard(generatePublicCard())}>生成卡密</Button>
      <TextInput type="datetime-local" label="首次领取截止时间" value={claimExpiry} disabled={busy} onChange={(event) => setClaimExpiry(event.currentTarget.value)} />
      <TextInput type="datetime-local" label="原交付找回截止时间" value={accessExpiry} disabled={busy} onChange={(event) => setAccessExpiry(event.currentTarget.value)} />
      <Checkbox label="已保存卡密，确认开放本包的卡密领取" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.currentTarget.checked)} />
      <Button variant="outline" disabled={busy || !confirmed || !card || !claimExpiry || !accessExpiry} onClick={() => void save(false)}>激活卡密领取</Button>
    </> : null}
    {card ? <Stack gap="xs">{status?.status !== 'not_activated' ? <TextInput label="本次卡密" value={card} readOnly /> : null}<Text size="sm">请保存卡密后交给客户</Text></Stack> : status?.cardSuffix ? <Text size="sm" c="dimmed">•••• {status.cardSuffix}</Text> : null}
    {active ? <><Checkbox label="确认撤销客户领取和找回权限" checked={confirmed} disabled={busy} onChange={(event) => setConfirmed(event.currentTarget.checked)} /><Button variant="outline" color="red" disabled={busy || !confirmed} onClick={() => void save(true)}>撤销卡密授权</Button></> : null}
    <Button size="xs" variant="subtle" disabled={busy} onClick={() => void reload()}>刷新卡密状态</Button>
  </Stack></Paper>;
}
