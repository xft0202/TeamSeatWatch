import { useMutation, useQuery } from '@tanstack/react-query';
import { App, Button, Descriptions, Drawer, Select, Spin, Table, Tabs } from 'antd';
import { useState } from 'react';
import { useSearchParams } from 'react-router';
import type { components } from '../generated/owner';
import { mutationHeaders, ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure } from './problems';

type DeliveryRecord = components['schemas']['DeliveryRecord'];

// 交付页（规格书 §5）：凭据是卖给客户的货。三个镜头看同一份交付事实——
// 交付状态看全局、凭据库存看修复、卡密与订单看兑换。找回/撤销是高风险动作，
// 二次确认必须写清影响范围和「什么不受影响」。

function serviceLabel(v: string | undefined) {
  if (v === 'active') return '服务中';
  if (v === 'ended') return '已结束';
  return '—';
}

function cardLabel(v: string | undefined) {
  return v === 'active' ? '有效' : v === 'revoked' ? '已撤销' : '未激活';
}

function orderLabel(v: string | undefined) {
  return v === 'claimed' ? '已兑换' : '未兑换';
}

function timeLabel(v: string | undefined) {
  return v ? new Date(v).toLocaleString() : '—';
}

function assetPill(v: string | undefined) {
  if (v === 'available') {
    return <span className="pill pill--ok"><span className="pill__dot" />可交付</span>;
  }
  if (v === 'unavailable') {
    return <span className="pill pill--zhu"><span className="pill__dot" />待修复</span>;
  }
  return <span className="pill pill--neutral">{v ?? '—'}</span>;
}

export default function DeliveryPage() {
  const { message, modal } = App.useApp();
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'inventory' || params.get('tab') === 'cards' ? params.get('tab') : 'status';
  const [detailId, setDetailId] = useState<string | undefined>(undefined);

  const serviceStatus =
    params.get('service_status') === 'active' || params.get('service_status') === 'ended'
      ? (params.get('service_status') as 'active' | 'ended')
      : undefined;
  const cardStatus =
    params.get('card_status') === 'unactivated' || params.get('card_status') === 'active' || params.get('card_status') === 'revoked'
      ? (params.get('card_status') as 'unactivated' | 'active' | 'revoked')
      : undefined;
  const orderStatus =
    params.get('order_status') === 'unclaimed' || params.get('order_status') === 'claimed'
      ? (params.get('order_status') as 'unclaimed' | 'claimed')
      : undefined;

  function updateParams(updates: Record<string, string | undefined>) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined) next.delete(key);
      else next.set(key, value);
    }
    setParams(next);
  }

  const deliveries = useQuery({
    queryKey: ['deliveries', 'page', serviceStatus, cardStatus, orderStatus],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/deliveries', {
        params: {
          query: {
            page: 1,
            page_size: 100,
            ...(serviceStatus ? { service_status: serviceStatus } : {}),
            ...(cardStatus ? { card_status: cardStatus } : {}),
            ...(orderStatus ? { order_status: orderStatus } : {}),
          },
        },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const detail = useQuery({
    queryKey: ['delivery', detailId],
    enabled: Boolean(detailId),
    queryFn: async () => {
      if (!detailId) throw new Error('请先选择一条交付');
      const response = await ownerApi.GET('/api/owner/v1/deliveries/{membershipId}', {
        params: { path: { membershipId: detailId } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const reclaim = useMutation({
    mutationFn: async (membershipId: string) => {
      const response = await ownerApi.POST('/api/owner/v1/deliveries/{membershipId}/reclaim', {
        params: { path: { membershipId }, header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID() },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      message.success('已授权，找回任务已排队。');
      await Promise.all([detail.refetch(), deliveries.refetch()]);
    },
    onError: (error) => message.error(error instanceof Error ? error.message : '找回授权失败'),
  });

  const revoke = useMutation({
    mutationFn: async (membershipId: string) => {
      const response = await ownerApi.POST('/api/owner/v1/deliveries/{membershipId}/card/revoke', {
        params: { path: { membershipId }, header: await mutationHeaders() },
        body: { confirm: true },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      message.success('已撤销这张卡的兑换和客户访问。');
      await Promise.all([detail.refetch(), deliveries.refetch()]);
    },
    onError: (error) => message.error(error instanceof Error ? error.message : '撤销失败'),
  });

  function confirmReclaim(row: DeliveryRecord) {
    modal.confirm({
      title: '找回这条凭据？',
      content: (
        <div style={{ lineHeight: 1.8 }}>
          <div>只恢复这个成员账号在这批的凭据，不换号、不延期、不新建订单。</div>
          <div>客户已经下载过的内容不受影响。</div>
        </div>
      ),
      okText: '开始找回',
      cancelText: '先不',
      onOk: () => reclaim.mutate(row.membershipId),
    });
  }

  function confirmRevoke(row: DeliveryRecord) {
    modal.confirm({
      title: '撤销这张卡？',
      content: (
        <div style={{ lineHeight: 1.8 }}>
          <div>撤销后不能再首次兑换，也不能再恢复原订单。</div>
          <div>不能远程抹除客户已经下载并保存的交付结果。</div>
        </div>
      ),
      okText: '确认撤销',
      cancelText: '先不',
      okButtonProps: { danger: true },
      onOk: () => revoke.mutate(row.membershipId),
    });
  }

  const filters = (
    <div className="toolbar">
      <Select
        aria-label="按服务状态筛选"
        allowClear
        value={serviceStatus}
        placeholder="全部服务状态"
        style={{ width: 140 }}
        onChange={(value) => updateParams({ service_status: value })}
        options={[
          { value: 'active', label: '服务中' },
          { value: 'ended', label: '已结束' },
        ]}
      />
      <Select
        aria-label="按卡密状态筛选"
        allowClear
        value={cardStatus}
        placeholder="全部卡密状态"
        style={{ width: 140 }}
        onChange={(value) => updateParams({ card_status: value })}
        options={[
          { value: 'unactivated', label: '未激活' },
          { value: 'active', label: '有效' },
          { value: 'revoked', label: '已撤销' },
        ]}
      />
      <Select
        aria-label="按订单状态筛选"
        allowClear
        value={orderStatus}
        placeholder="全部订单状态"
        style={{ width: 140 }}
        onChange={(value) => updateParams({ order_status: value })}
        options={[
          { value: 'unclaimed', label: '未兑换' },
          { value: 'claimed', label: '已兑换' },
        ]}
      />
    </div>
  );

  // 共享列定义为独立对象，避免数组索引取值（noUncheckedIndexedAccess）
  const workspaceCol = { title: '空间', dataIndex: 'workspaceName', key: 'workspace', width: 110 };
  const assetCol = {
    title: '交付状态',
    dataIndex: 'assetStatus',
    key: 'asset',
    width: 110,
    render: (v: string | undefined) => assetPill(v),
  };
  const livenessCol = {
    title: '凭据状态',
    key: 'liveness',
    width: 120,
    render: (_: unknown, row: DeliveryRecord) => row.livenessStatus ?? '尚未检查',
  };
  const probedCol = {
    title: '探测时间',
    key: 'probed',
    width: 170,
    render: (_: unknown, row: DeliveryRecord) => (
      <span className="mono" style={{ fontSize: 12, color: 'var(--ink-3)' }}>
        {timeLabel(row.probedAt)}
      </span>
    ),
  };

  const baseColumns = [
    workspaceCol,
    {
      title: '服务',
      dataIndex: 'serviceStatus',
      key: 'service',
      width: 90,
      render: (v: string | undefined) => serviceLabel(v),
    },
    assetCol,
    livenessCol,
    probedCol,
  ];

  const inventoryColumns = [
    workspaceCol,
    assetCol,
    livenessCol,
    {
      title: '找回状态',
      key: 'reclaim',
      width: 130,
      render: (_: unknown, row: DeliveryRecord) =>
        row.reclaimStatus ? `${row.reclaimStatus}${row.reclaimTier ? ` · ${row.reclaimTier}` : ''}` : '未请求',
    },
    probedCol,
    {
      title: '',
      key: 'actions',
      width: 90,
      render: (_: unknown, row: DeliveryRecord) =>
        row.assetStatus === 'unavailable' ? (
          <Button type="link" size="small" onClick={() => confirmReclaim(row)}>
            找回
          </Button>
        ) : null,
    },
  ];

  const cardColumns = [
    workspaceCol,
    {
      title: '卡密',
      key: 'card',
      width: 110,
      render: (_: unknown, row: DeliveryRecord) =>
        row.cardStatus === 'active' ? (
          <span className="pill pill--ok"><span className="pill__dot" />有效</span>
        ) : row.cardStatus === 'revoked' ? (
          <span className="pill pill--zhu"><span className="pill__dot" />已撤销</span>
        ) : (
          <span className="pill pill--neutral">未激活</span>
        ),
    },
    {
      title: '尾号',
      key: 'suffix',
      width: 80,
      render: (_: unknown, row: DeliveryRecord) => (
        <span className="mono" style={{ fontSize: 12 }}>{row.cardDisplaySuffix ?? '—'}</span>
      ),
    },
    {
      title: '订单',
      key: 'order',
      width: 90,
      render: (_: unknown, row: DeliveryRecord) => orderLabel(row.orderStatus),
    },
    {
      title: '兑换截止',
      key: 'deadline',
      width: 170,
      render: (_: unknown, row: DeliveryRecord) => (
        <span className="mono" style={{ fontSize: 12, color: 'var(--ink-3)' }}>
          {timeLabel(row.redemptionDeadline)}
        </span>
      ),
    },
    {
      title: '',
      key: 'actions',
      width: 90,
      render: (_: unknown, row: DeliveryRecord) =>
        row.cardStatus === 'active' || row.cardStatus === 'unactivated' ? (
          <Button type="link" size="small" danger onClick={() => confirmRevoke(row)}>
            撤销
          </Button>
        ) : null,
    },
  ];

  const items = deliveries.data?.items ?? [];
  const attentionCount = items.filter((i) => i.assetStatus === 'unavailable').length;

  return (
    <OwnerShell fullBleed>
      <main className="page">
        <span className="micro">交付</span>
        <h1 className="page__title">交付</h1>

        <Tabs
          activeKey={tab ?? 'status'}
          onChange={(next) => updateParams({ tab: next })}
          items={[
            {
              key: 'status',
              label: `交付状态${attentionCount > 0 ? ` · ${attentionCount} 待修复` : ''}`,
              children: (
                <>
                  {filters}
                  <Table
                    size="small"
                    rowKey="membershipId"
                    pagination={false}
                    columns={baseColumns}
                    dataSource={items}
                    onRow={(row) => ({
                      onClick: () => setDetailId(row.membershipId),
                      style: { cursor: 'pointer' },
                    })}
                  />
                </>
              ),
            },
            {
              key: 'inventory',
              label: '凭据库存',
              children: (
                <>
                  {filters}
                  <Table
                    size="small"
                    rowKey="membershipId"
                    pagination={false}
                    columns={inventoryColumns}
                    dataSource={items}
                    onRow={(row) => ({
                      onClick: () => setDetailId(row.membershipId),
                      style: { cursor: 'pointer' },
                    })}
                  />
                </>
              ),
            },
            {
              key: 'cards',
              label: '卡密与订单',
              children: (
                <>
                  {filters}
                  <Table
                    size="small"
                    rowKey="membershipId"
                    pagination={false}
                    columns={cardColumns}
                    dataSource={items}
                    onRow={(row) => ({
                      onClick: () => setDetailId(row.membershipId),
                      style: { cursor: 'pointer' },
                    })}
                  />
                </>
              ),
            },
          ]}
        />

        {deliveries.isLoading ? <Spin style={{ marginTop: 12 }} /> : null}
        {deliveries.isError ? (
          <div className="quietnote" style={{ marginTop: 12 }}>
            交付读取失败：{deliveries.error instanceof Error ? deliveries.error.message : '未知错误'}
          </div>
        ) : null}
      </main>

      <Drawer
        title="交付明细"
        open={Boolean(detailId)}
        onClose={() => setDetailId(undefined)}
        size={440}
      >
        {detail.data ? (
          <>
            <Descriptions
              column={1}
              size="small"
              items={[
                { key: 'workspace', label: '空间', children: detail.data.workspaceName ?? '—' },
                { key: 'service', label: '服务', children: serviceLabel(detail.data.serviceStatus) },
                { key: 'asset', label: '交付状态', children: detail.data.assetStatus },
                { key: 'liveness', label: '凭据状态', children: detail.data.livenessStatus ?? '尚未检查' },
                { key: 'card', label: '卡密', children: cardLabel(detail.data.cardStatus) },
                { key: 'order', label: '订单', children: orderLabel(detail.data.orderStatus) },
                { key: 'probed', label: '最近探测', children: timeLabel(detail.data.probedAt) },
                { key: 'reclaim', label: '找回状态', children: detail.data.reclaimStatus ?? '未请求' },
              ]}
            />
            <div style={{ marginTop: 16, display: 'flex', gap: 8 }}>
              {detail.data.assetStatus === 'unavailable' ? (
                <Button loading={reclaim.isPending} onClick={() => confirmReclaim(detail.data!)}>
                  找回
                </Button>
              ) : null}
              {detail.data.cardStatus === 'active' || detail.data.cardStatus === 'unactivated' ? (
                <Button danger onClick={() => confirmRevoke(detail.data!)}>
                  撤销
                </Button>
              ) : null}
            </div>
          </>
        ) : (
          <Spin />
        )}
      </Drawer>
    </OwnerShell>
  );
}
