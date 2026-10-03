import { Alert, Badge, Button, Container, Group, Paper, Select, Stack, Text, Textarea, Title } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { publicApi, publicErrorMessage, type Confirmation, type DeliveryState, type RecoveryState } from './api';
import { canDownload, createPublicRequests, MAX_CARDS, parseCards } from './redeemState';

type CardResult = { secret: string; suffix: string; state?: Confirmation; error?: string };
export default function RedeemPage() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState<CardResult[]>([]);
  const [selected, setSelected] = useState('');
  const [state, setState] = useState<Confirmation | DeliveryState>();
  const [recovery, setRecovery] = useState<RecoveryState>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const requests = useRef(createPublicRequests()).current;
  const cards = parseCards(input);
  const selectedCard = results[Number(selected)]?.secret ?? (cards.length === 1 ? cards[0] : undefined);
  async function operation(action: (token: number) => Promise<void>) {
    const token = requests.begin(); if (token === null) return;
    setBusy(true); setError('');
    try { await action(token); } catch (e) { if (requests.current(token)) { setError(publicErrorMessage(e)); if (e instanceof Error && (e.message === 'public_request_denied' || e.message === 'public_request_invalid')) setState(undefined); } }
    finally { if (requests.finish(token)) setBusy(false); }
  }
  useEffect(() => {
    void operation(async (token) => {
      try { const next = await publicApi.state(); if (requests.current(token)) setState(next); } catch { /* A fresh visitor has no authorization. */ }
    });
    return () => requests.invalidate();
  }, []);
  async function claim() {
    await operation(async (token) => {
      const next: CardResult[] = [];
      for (const secret of cards) {
        if (!requests.current(token)) return;
        try {
          const confirmation = await publicApi.confirm(secret);
          next.push({ secret, suffix: confirmation.cardSuffix, state: confirmation });
        } catch (e) { next.push({ secret, suffix: '••••', error: publicErrorMessage(e) }); }
        if (requests.current(token)) setResults([...next]);
      }
      if (!requests.current(token)) return;
      let last = -1;
      next.forEach((item, index) => { if (item.state) last = index; });
      setSelected(String(Math.max(0, last))); setRecovery(undefined);
      // Every failed response may have reached the service. Restoring the chosen
      // original card confirms which order now owns the browser cookie.
      const chosen = next[last];
      if (chosen) setState(await publicApi.confirm(chosen.secret));
      else { setState(undefined); setError(next[0]?.error ?? '当前卡密不可用'); }
    });
  }
  async function selectCard(value: string | null) {
    if (value === null) return;
    await operation(async (token) => {
      setSelected(value); setState(undefined); setRecovery(undefined);
      const item = results[Number(value)]; if (!item) return;
      const next = await publicApi.confirm(item.secret);
      if (requests.current(token)) setState(next);
    });
  }
  async function reload() {
    await operation(async (token) => {
      if (pendingRecovery) {
        const progress = await publicApi.recovery();
        if (requests.current(token)) setRecovery(progress);
      }
      const next = await publicApi.state();
      if (requests.current(token)) setState(next);
    });
  }
  async function recover() {
    if (!selectedCard) return;
    await operation(async (token) => {
      const next = await publicApi.recover(selectedCard);
      if (!requests.current(token)) return;
      setRecovery(next);
      if (next.deliveryStatus === 'available') {
        const original = await publicApi.state(); if (requests.current(token)) setState(original);
      } else { setState(undefined); }
    });
  }
  async function download() {
    await operation(async (token) => {
      if (selectedCard) {
        const current = await publicApi.confirm(selectedCard);
        if (!requests.current(token)) return;
        setState(current); if (!canDownload(current)) throw new Error('public_delivery_pending');
      }
      const file = await publicApi.download(); if (!requests.current(token)) return;
      const url = URL.createObjectURL(file.blob);
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = file.filename;
      document.body.append(anchor); anchor.click(); anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  }
  const pendingRecovery = recovery?.status === 'queued' || recovery?.status === 'running' || recovery?.status === 'retry_wait';
  return <Container size={840} className="public-content">
    <Stack gap={32}>
      <div><Text size="sm" c="dimmed">客户领取</Text><Title order={1} className="public-title">领取你的交付包</Title></div>
      <Paper withBorder radius={12} p={32} component="section" aria-label="输入卡密">
        <Stack gap={20}>
          <Textarea label="卡密" placeholder="粘贴卡密，多张卡密每行一张" minRows={3} maxRows={8} autosize autoComplete="off" spellCheck={false} value={input} disabled={busy} onChange={(event) => { setInput(event.currentTarget.value); if (results.length === 0) { setState(undefined); setRecovery(undefined); } }} />
          <Group justify="space-between"><Text size="sm" c="dimmed">{cards.length} 张卡密</Text><Button loading={busy} disabled={busy || cards.length === 0 || cards.length > MAX_CARDS} onClick={() => void claim()}>领取</Button></Group>
          {cards.length > MAX_CARDS ? <Text c="red" role="alert">每次最多处理 {MAX_CARDS} 张卡密</Text> : null}
        </Stack>
      </Paper>
      {error ? <Alert color="red" role="alert">{error}</Alert> : null}
      {results.length > 1 ? <Paper withBorder radius={12} p={24}><Stack gap="sm"><Select label="查看领取结果" value={selected} disabled={busy} data={results.map((item, index) => ({ value: String(index), label: `${index + 1}. •••• ${item.suffix} · ${item.error ? '待处理' : item.state?.action === 'restored' ? '原交付' : '已领取'}` }))} onChange={(value) => void selectCard(value)} />{results[Number(selected)]?.error ? <Text size="sm" c="red">{results[Number(selected)]?.error}</Text> : null}</Stack></Paper> : null}
      <Paper withBorder radius={12} p={32} component="section" aria-label="原交付状态"><Stack gap={20}>
        <Group justify="space-between"><Title order={2} size={24}>原交付</Title><Badge color={canDownload(state) ? 'success' : 'gray'}>{pendingRecovery ? '找回中' : canDownload(state) ? '可下载' : state?.hasOrder ? '待处理' : '尚未领取'}</Badge></Group>
        {state?.hasOrder ? <Text size="sm" c="dimmed">•••• {state.cardSuffix}{state.accountCount ? ` · ${state.accountCount} 个子号` : ''}</Text> : null}
        {state?.hasOrder && state.deliveryFormat !== 'zip' ? <Text size="sm">原交付需要交付方处理，请保留卡密</Text> : null}
        {canDownload(state) ? <Button variant="outline" disabled={busy} onClick={() => void download()}>下载原交付 ZIP</Button> : null}
        {pendingRecovery ? <Text size="sm">原交付正在找回，请稍后查看状态</Text> : recovery?.deliveryStatus === 'available' ? <Text size="sm">已找回原交付</Text> : null}
        <Group><Button variant="subtle" disabled={busy} onClick={() => void reload()}>查看状态</Button><Button variant="subtle" disabled={busy || !selectedCard} onClick={() => void recover()}>找回原交付</Button></Group>
      </Stack></Paper>
    </Stack>
  </Container>;
}
