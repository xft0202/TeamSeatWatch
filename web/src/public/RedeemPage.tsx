import { Alert, Button, Input, List, Progress, Steps, Tag, Typography } from 'antd';
import { useEffect, useMemo, useState } from 'react';
import { checkCredentialStatus, confirmRedeem, downloadDelivery, getReclaimStatus, requestReclaim } from './api';

const MAX_CARDS = 2000;

type RedeemResult = {
  id: number;
  cardSuffix: string;
  action: string;
  status: 'success' | 'error';
  message: string;
  remainingSeconds?: number;
  payload?: Blob;
};

type ZipEntry = { name: string; data: Uint8Array };

function crc32(data: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function makeZip(entries: ZipEntry[]) {
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const write = (size: number, fill: (view: DataView) => void) => {
    const bytes = new Uint8Array(size);
    fill(new DataView(bytes.buffer));
    chunks.push(bytes);
    offset += size;
    return bytes;
  };
  for (const entry of entries) {
    const name = encoder.encode(entry.name);
    const crc = crc32(entry.data);
    const localOffset = offset;
    write(30 + name.length, (view) => {
      view.setUint32(0, 0x04034b50, true); view.setUint16(4, 20, true); view.setUint16(6, 0, true);
      view.setUint16(8, 0, true); view.setUint16(10, 0, true); view.setUint16(12, 0, true);
      view.setUint32(14, crc, true); view.setUint32(18, entry.data.length, true); view.setUint32(22, entry.data.length, true);
      view.setUint16(26, name.length, true); view.setUint16(28, 0, true);
    });
    chunks.push(name); offset += name.length;
    chunks.push(entry.data); offset += entry.data.length;
    const centralRecord = new Uint8Array(46 + name.length);
    const view = new DataView(centralRecord.buffer);
    view.setUint32(0, 0x02014b50, true); view.setUint16(4, 20, true); view.setUint16(6, 20, true);
    view.setUint16(8, 0, true); view.setUint16(10, 0, true); view.setUint16(12, 0, true); view.setUint16(14, 0, true);
    view.setUint32(16, crc, true); view.setUint32(20, entry.data.length, true); view.setUint32(24, entry.data.length, true);
    view.setUint16(28, name.length, true); view.setUint16(30, 0, true); view.setUint16(32, 0, true); view.setUint16(34, 0, true);
    view.setUint16(36, 0, true); view.setUint32(38, 0, true); view.setUint32(42, localOffset, true);
    centralRecord.set(name, 46); central.push(centralRecord);
  }
  const centralOffset = offset;
  for (const record of central) { chunks.push(record); offset += record.length; }
  write(22, (view) => {
    view.setUint32(0, 0x06054b50, true); view.setUint16(4, 0, true); view.setUint16(6, 0, true);
    view.setUint16(8, entries.length, true); view.setUint16(10, entries.length, true); view.setUint32(12, offset - centralOffset, true);
    view.setUint32(16, centralOffset, true); view.setUint16(20, 0, true);
  });
  return new Blob(chunks.map((chunk) => new Uint8Array(chunk).buffer as ArrayBuffer), { type: 'application/zip' });
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function reclaimStageLabel(stage?: string) {
  switch (stage) {
    case 'probe': return '正在检查凭据';
    case 'refresh': return '正在尝试恢复';
    case 'relogin': return '正在重新登录';
    case 'publish': return '正在确认并发布';
    default: return '未开始';
  }
}

function readableError(error: unknown) {
  if (error instanceof Error && error.message === 'public_rate_limited') return '请求过于频繁，请稍后再试。';
  if (error instanceof Error && error.message === 'public_request_denied') return '当前卡密无法完成兑换。';
  return '当前请求未完成，请稍后重试。';
}

function actionLabel(action: string) {
  return action === 'restored' ? '已恢复原订单' : '已直接兑换';
}

export default function RedeemPage() {
  const [input, setInput] = useState('');
  const [results, setResults] = useState<RedeemResult[]>([]);
  const [running, setRunning] = useState(false);
  const [zipReady, setZipReady] = useState(false);
  const [credentialStatus, setCredentialStatus] = useState<string>();
  const [reclaimStatus, setReclaimStatus] = useState<Awaited<ReturnType<typeof getReclaimStatus>>>();
  const [reclaimBusy, setReclaimBusy] = useState(false);
  const cards = useMemo(() => Array.from(new Set(input.split(/[\s,，]+/).map((value) => value.trim()).filter(Boolean))), [input]);
  const singleCard = cards.length === 1 ? cards[0] : undefined;
  const reclaimInProgress = reclaimBusy || reclaimStatus?.result === 'queued' || reclaimStatus?.result === 'checking';

  useEffect(() => {
    const status = reclaimStatus?.status;
    if (!status || !['queued', 'running', 'retry_wait'].includes(status)) return undefined;
    const timer = window.setInterval(() => {
      void getReclaimStatus().then(setReclaimStatus).catch(() => undefined);
    }, Math.max(2000, (reclaimStatus?.retryAfterSeconds ?? 3) * 1000));
    return () => window.clearInterval(timer);
  }, [reclaimStatus]);

  async function checkStatus() {
    if (!singleCard || reclaimBusy || running) return;
    setReclaimBusy(true);
    try {
      const result = await checkCredentialStatus(singleCard);
      setCredentialStatus(result.status);
    } catch (error) {
      setCredentialStatus(readableError(error));
    } finally {
      setReclaimBusy(false);
    }
  }

  async function startReclaim() {
    if (!singleCard || reclaimBusy || running) return;
    setReclaimBusy(true);
    try {
      setReclaimStatus(await requestReclaim(singleCard));
    } catch (error) {
      setReclaimStatus(undefined);
      setCredentialStatus(readableError(error));
    } finally {
      setReclaimBusy(false);
    }
  }

  async function redeem() {
    if (cards.length === 0 || cards.length > MAX_CARDS || running) return;
    setRunning(true); setZipReady(false); setResults([]);
    const successful: ZipEntry[] = [];
    const summary: Array<{ card: string; status: string; action?: string; message: string }> = [];
    const next: RedeemResult[] = [];
    for (const [index, secret] of cards.entries()) {
      try {
        const confirmation = await confirmRedeem(secret);
        const payload = await downloadDelivery();
        const raw = JSON.parse(await payload.text()) as Record<string, unknown>;
        const credentials = {
          access_token: String(raw.access_token ?? ''),
          refresh_token: String(raw.refresh_token ?? ''),
          id_token: String(raw.id_token ?? ''),
          chatgpt_account_id: String(raw.platform_subject_id ?? ''),
          expires_in: Number(raw.expires_in ?? 0),
          workspace_id: String(raw.workspace_id ?? ''),
        };
        const sub2api = {
          accounts: [{
            name: confirmation.cardSuffix,
            platform: 'openai',
            type: 'codex',
            credentials,
          }],
        };
        const cpa = {
          id_token: credentials.id_token,
          client_id: 'app_EMoamEEZ73f0CkXaXp7hrann',
          access_token: credentials.access_token,
          refresh_token: credentials.refresh_token,
          account_id: credentials.chatgpt_account_id,
          last_refresh: new Date().toISOString(),
          type: 'codex',
          expired: '',
          password: 'Takeover_NoPassword',
          plan_type: 'free',
        };
        successful.push({ name: `sub2api/${confirmation.cardSuffix}-${index + 1}.json`, data: new TextEncoder().encode(JSON.stringify(sub2api, null, 2)) });
        successful.push({ name: `cpa/${confirmation.cardSuffix}-${index + 1}.json`, data: new TextEncoder().encode(JSON.stringify(cpa, null, 2)) });
        summary.push({ card: confirmation.cardSuffix, status: 'success', action: confirmation.action, message: actionLabel(confirmation.action) });
        next.push({ id: index, cardSuffix: confirmation.cardSuffix, action: confirmation.action, status: 'success', message: actionLabel(confirmation.action), remainingSeconds: confirmation.remainingSeconds, payload });
      } catch (error) {
        const failureMessage = readableError(error);
        next.push({ id: index, cardSuffix: '••••', action: '', status: 'error', message: failureMessage });
        summary.push({ card: '••••', status: 'error', message: failureMessage });
      }
      setResults([...next]);
    }
    if (successful.length > 0) {
      successful.push({ name: 'summary.json', data: new TextEncoder().encode(JSON.stringify(summary, null, 2)) });
      triggerDownload(makeZip(successful), 'teamseatwatch-delivery.zip');
      setZipReady(true);
    }
    setRunning(false);
  }

  return (
    <section className="redeem-page" aria-labelledby="redeem-title">
      <div className="redeem-intro">
        <p className="eyebrow">TeamSeatWatch 公网兑换端</p>
        <Typography.Title id="redeem-title" level={1}>直接兑换</Typography.Title>
        <Typography.Paragraph>粘贴一张或多张卡密，每行一张；系统自动判断首次兑换或恢复原订单，完成后统一下载一个 ZIP。</Typography.Paragraph>
      </div>
      <div className="redeem-stack">
        <Input.TextArea
          value={input}
          onChange={(event) => setInput(event.target.value)}
          disabled={running}
          autoSize={{ minRows: 5, maxRows: 14 }}
          placeholder="单卡：粘贴一张卡密\n多卡：每行一张卡密"
          autoComplete="off"
          spellCheck={false}
        />
        <div className="redeem-action-row">
          <Typography.Text type="secondary">已识别 {cards.length}/{MAX_CARDS} 张</Typography.Text>
          <Button type="primary" size="large" loading={running} disabled={cards.length === 0 || cards.length > MAX_CARDS || reclaimInProgress || reclaimStatus?.deliveryStatus === 'unavailable'} onClick={() => void redeem()}>
            {running ? '兑换中…' : '立即兑换并下载 ZIP'}
          </Button>
        </div>
      </div>
      <Alert
        type="info"
        showIcon
        title="交付凭据操作"
        description="凭据状态检查只读取并记录当前状态；请求找回会恢复原卡绑定的交付单元，不会创建新订单。"
        action={
          <div className="redeem-action-row">
            <Button loading={reclaimBusy} disabled={!singleCard || running} onClick={() => void checkStatus()}>检查凭据状态</Button>
            <Button type="primary" loading={reclaimBusy} disabled={!singleCard || running} onClick={() => void startReclaim()}>请求找回</Button>
          </div>
        }
      />
      {(credentialStatus || reclaimStatus) ? (
        <section aria-labelledby="reclaim-progress-title">
          <Typography.Title level={4} id="reclaim-progress-title">当前交付处理</Typography.Title>
          <Steps
            current={reclaimStatus?.result === 'restored' || reclaimStatus?.result === 'unrecoverable' ? 2 : reclaimStatus ? 1 : 0}
            {...(reclaimStatus?.result === 'unrecoverable' ? { status: 'error' as const } : {})}
            items={[
              { title: '检查凭据', description: credentialStatus === 'healthy' ? '当前可用' : credentialStatus === 'need_reclaim' ? '需要找回' : credentialStatus ?? '尚未检查' },
              { title: '尝试恢复', description: reclaimStatus?.result === 'checking' ? reclaimStageLabel(reclaimStatus.stage) : reclaimStatus?.result === 'queued' ? '已排队' : reclaimStatus?.result === 'restored' ? '已恢复' : reclaimStatus?.result === 'unrecoverable' ? '不可恢复' : '未请求' },
              { title: '交付状态', description: reclaimStatus?.deliveryStatus === 'available' ? '可下载' : '暂不可下载' },
            ]}
          />
          {reclaimStatus?.result === 'unrecoverable' ? <Alert type="error" showIcon title="当前凭据不可恢复" description="交付保持暂停，请联系系统所有者处理新的授权。" /> : null}
          {reclaimStatus?.result === 'restored' ? <Alert type="success" showIcon title="交付已恢复" description="当前版本已发布，可以重新兑换原订单后下载。" /> : null}
        </section>
      ) : null}
      {running || results.length > 0 ? <Progress percent={cards.length ? Math.round((results.length / cards.length) * 100) : 0} status={running ? 'active' : 'normal'} /> : null}
      {zipReady ? <Tag color="success">已生成一个 ZIP，内含成功卡的 JSON 交付</Tag> : null}
      {results.length > 0 ? (
        <List
          bordered
          header={<Typography.Text strong>兑换结果</Typography.Text>}
          dataSource={results}
          renderItem={(item) => <List.Item><span>•••• {item.cardSuffix}</span><span><Tag color={item.status === 'success' ? 'success' : 'error'}>{item.status === 'success' ? actionLabel(item.action) : '失败'}</Tag>{item.message}</span></List.Item>}
        />
      ) : null}
    </section>
  );
}
