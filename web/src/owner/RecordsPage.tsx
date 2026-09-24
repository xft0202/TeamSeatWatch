import { ExclamationCircleOutlined, RedoOutlined, DownloadOutlined } from '@ant-design/icons';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Alert, Button, Descriptions, Drawer, Empty, Input, message, Modal, Popconfirm, Select, Space, Spin, Table, Tabs, Tag, Typography } from 'antd';
import { useNavigate, useSearchParams } from 'react-router';
import { useState } from 'react';
import type { components } from '../generated/owner';
import { ownerApi, mutationHeaders } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure } from './problems';

type Workspace = components['schemas']['Workspace'];
type JoinOperation = components['schemas']['JoinOperation'];
type RemovalOperation = components['schemas']['RemovalOperation'];
type DeliveryRecord = components['schemas']['DeliveryRecord'];
type DeliveryRecordEvent = components['schemas']['DeliveryRecordEvent'];
type AuditEvent = components['schemas']['AuditEvent'];

function JoinAttentionTable({ items, onHandle, onReconcile, loading }: { items: JoinOperation[]; onHandle: (id: string) => void; onReconcile: (id: string) => void; loading: boolean }) {
  if (items.length === 0) return null;
  return <>
    <Typography.Title level={4}>需要处理的加入操作</Typography.Title>
    <Table<JoinOperation>
      size="small"
      rowKey="id"
      dataSource={items}
      scroll={{ x: 760 }}
      pagination={false}
      columns={[
        { title: '目标总数', dataIndex: 'targetTotal', key: 'target' },
        { title: '操作状态', dataIndex: 'status', key: 'status' },
        { title: '结果', key: 'result', render: (_, item) => `${item.succeededCount} 成功 / ${item.failedCount} 失败 / ${item.blockedCount} 阻塞 / ${item.pendingCount} 待处理` },
        { title: '处理', key: 'action', render: (_, item) => <Space><Button size="small" loading={loading} onClick={() => onReconcile(item.batchId)}>核对成员事实</Button><Button size="small" onClick={() => onHandle(item.batchId)}>返回第 4 步</Button></Space> },
      ]}
    />
  </>;
}

function RemovalAttentionTable({ items, onHandle }: { items: RemovalOperation[]; onHandle: (id: string) => void }) {
  if (items.length === 0) return null;
  return <>
    <Typography.Title level={4}>需要处理的精确移除</Typography.Title>
    <Table<RemovalOperation>
      size="small"
      rowKey="id"
      dataSource={items}
      scroll={{ x: 760 }}
      pagination={false}
      columns={[
        { title: '目标总数', dataIndex: 'targetTotal', key: 'target' },
        { title: '操作状态', dataIndex: 'status', key: 'status' },
        { title: '结果', key: 'result', render: (_, item) => `${item.succeededCount} 已确认移除 / ${item.blockedCount} 阻塞 / ${item.pendingCount} 待处理` },
        { title: '处理', key: 'action', render: (_, item) => <Button size="small" onClick={() => onHandle(item.batchId)}>返回第 6 步读取最新事实</Button> },
      ]}
    />
  </>;
}

function AuditTable({ data, page, pageSize, onPage }: { data: components['schemas']['AuditEventList'] | undefined; page: number; pageSize: number; onPage: (page: number, pageSize: number) => void }) {
  return <Table<AuditEvent>
    rowKey={(item) => `${item.occurredAt}-${item.eventType}-${item.correlationId}`}
    size="small"
    scroll={{ x: 980 }}
    pagination={{ current: data?.page ?? page, pageSize: data?.pageSize ?? pageSize, total: data?.total ?? 0, showSizeChanger: true }}
    onChange={(pagination) => onPage(pagination.current ?? 1, pagination.pageSize ?? 20)}
    dataSource={data?.items ?? []}
    columns={[
      { title: '时间', dataIndex: 'occurredAt', key: 'time', render: (value: string) => new Date(value).toLocaleString() },
      { title: '操作者', dataIndex: 'actor', key: 'actor' },
      { title: '事件', dataIndex: 'eventType', key: 'event' },
      { title: '结果', dataIndex: 'outcome', key: 'outcome' },
      { title: '对象', dataIndex: 'entityType', key: 'entity' },
      { title: '关联链', dataIndex: 'correlationId', key: 'correlation' },
      { title: '详情', dataIndex: 'details', key: 'details', render: (value: Record<string, unknown>) => JSON.stringify(value) },
    ]}
  />;
}
function ProjectionTable({ items, page, pageSize, total, onPage, onHandle }: {
  items: Workspace[];
  page: number;
  pageSize: number;
  total: number;
  onPage: (page: number, pageSize: number) => void;
  onHandle: (id: string) => void;
}) {
  if (items.length === 0) return <Empty description="当前没有记录" />;
  return (
    <Table<Workspace>
      size="small"
      rowKey="id"
      pagination={{ current: page, pageSize, total, showSizeChanger: true }}
      onChange={(pagination) => onPage(pagination.current ?? 1, pagination.pageSize ?? 20)}
      dataSource={items}
      scroll={{ x: 680 }}
      columns={[
        { title: '团队空间', dataIndex: 'displayName', key: 'name' },
        {
          title: '当前结论',
          key: 'state',
          render: (_: unknown, item: Workspace) => (
            <Tag icon={<ExclamationCircleOutlined />} {...(item.operationalState === 'deactivated' ? { color: 'error' } : {})}>
              {item.operationalState === 'unknown' ? '证据不足' : item.operationalState === 'operational' ? '当前可运营' : item.operationalState === 'deactivated' ? '已停用' : '团队空间不存在'}
            </Tag>
          ),
        },
        { title: '当前采用到期时间', key: 'active', render: (_: unknown, item: Workspace) => item.activeUntil ? new Date(item.activeUntil).toLocaleString() : '尚未读取' },
        { title: '观察时间', dataIndex: 'updatedAt', key: 'updated', render: (value: string) => new Date(value).toLocaleString() },
        { title: '操作', key: 'action', render: (_: unknown, item: Workspace) => <Button size="small" onClick={() => onHandle(item.id)}>前往处理</Button> },
      ]}
    />
  );
}

export default function RecordsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tabValue = params.get('tab');
  const tab = tabValue === 'attention' || tabValue === 'deliveries' || tabValue === 'audit' ? tabValue : 'workspaces';
  const parsedPage = Number(params.get('page') ?? '1');
  const parsedPageSize = Number(params.get('page_size') ?? '20');
  const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;
  const pageSize = Number.isInteger(parsedPageSize) && parsedPageSize >= 1 && parsedPageSize <= 100 ? parsedPageSize : 20;
  const requestedState = params.get('operational_state');
  const state: Workspace['operationalState'] | undefined = requestedState === 'unknown' || requestedState === 'operational' || requestedState === 'deactivated' || requestedState === 'not_found' ? requestedState : undefined;
  const requestedServiceStatus = params.get('service_status');
  const serviceStatus = requestedServiceStatus === 'active' || requestedServiceStatus === 'ended' ? requestedServiceStatus : undefined;
  const requestedCardStatus = params.get('card_status');
  const cardStatus = requestedCardStatus === 'unactivated' || requestedCardStatus === 'active' || requestedCardStatus === 'revoked' ? requestedCardStatus : undefined;
  const requestedOrderStatus = params.get('order_status');
  const orderStatus = requestedOrderStatus === 'unclaimed' || requestedOrderStatus === 'claimed' ? requestedOrderStatus : undefined;

  const requestedAuditActor = params.get('audit_actor');
  const auditActor = requestedAuditActor === 'owner' || requestedAuditActor === 'system' || requestedAuditActor === 'anonymous' ? requestedAuditActor : undefined;
  const requestedAuditOutcome = params.get('audit_outcome');
  const auditOutcome = requestedAuditOutcome === 'succeeded' || requestedAuditOutcome === 'failed' || requestedAuditOutcome === 'denied' ? requestedAuditOutcome : undefined;
  const auditEventType = params.get('audit_event_type') ?? undefined;
  const auditCorrelationId = params.get('audit_correlation_id') ?? undefined;
  const updateParams = (updates: Record<string, string | undefined>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined) next.delete(key); else next.set(key, value);
    }
    setParams(next);
  };
  const all = useQuery({
    queryKey: ['records-workspaces', page, pageSize, state],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/workspaces', { params: { query: { page, page_size: pageSize, sort: 'active_until_asc', ...(state ? { operational_state: state } : {}) } } });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const attention = useQuery({
    queryKey: ['records-attention', page, pageSize],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/workspaces/needs-attention', { params: { query: { page, page_size: pageSize } } });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const joinAttention = useQuery({
    queryKey: ['records-join-attention', page, pageSize],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/join-operations/needs-attention', { params: { query: { page, page_size: pageSize } } });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const removalAttention = useQuery({
    queryKey: ['records-removal-attention', page, pageSize],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/removal-operations/needs-attention', { params: { query: { page, page_size: pageSize } } });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const [deliveryMembershipID, setDeliveryMembershipID] = useState<string>();
  const [revokeModalOpen, setRevokeModalOpen] = useState(false);
  const deliveryList = useQuery({
    queryKey: ['records-deliveries', page, pageSize, serviceStatus, cardStatus, orderStatus],
    enabled: tab === 'deliveries',
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/deliveries', { params: { query: {
        page, page_size: pageSize,
        ...(serviceStatus ? { service_status: serviceStatus } : {}),
        ...(cardStatus ? { card_status: cardStatus } : {}),
        ...(orderStatus ? { order_status: orderStatus } : {}),
      } } });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const deliveryDetail = useQuery({
    queryKey: ['records-delivery', deliveryMembershipID],
    enabled: Boolean(deliveryMembershipID),
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/deliveries/{membershipId}', { params: { path: { membershipId: deliveryMembershipID! } } });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const audit = useQuery({
    queryKey: ['records-audit', page, pageSize, auditActor, auditOutcome, auditEventType, auditCorrelationId],
    enabled: tab === 'audit',
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/audit-events', { params: { query: {
        page, page_size: pageSize,
        ...(auditActor ? { actor: auditActor } : {}),
        ...(auditOutcome ? { outcome: auditOutcome } : {}),
        ...(auditEventType ? { event_type: auditEventType } : {}),
        ...(auditCorrelationId ? { correlation_id: auditCorrelationId } : {}),
      } } });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const auditExportURL = (format: 'json' | 'csv') => {
    const query = new URLSearchParams({ format });
    if (auditActor) query.set('actor', auditActor);
    if (auditOutcome) query.set('outcome', auditOutcome);
    if (auditEventType) query.set('event_type', auditEventType);
    if (auditCorrelationId) query.set('correlation_id', auditCorrelationId);
    return `/api/owner/v1/audit-events/export?${query.toString()}`;
  };
  const deliveryReclaim = useMutation({
    mutationFn: async (membershipId: string) => {
      const response = await ownerApi.POST('/api/owner/v1/deliveries/{membershipId}/reclaim', {
        params: { path: { membershipId }, header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID() },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      message.success('已授权，找回任务已排队');
      await Promise.all([deliveryDetail.refetch(), deliveryList.refetch()]);
    },
  });
  const deliveryCardRevoke = useMutation({
    mutationFn: async (membershipId: string) => {
      const response = await ownerApi.POST('/api/owner/v1/deliveries/{membershipId}/card/revoke', {
        params: { path: { membershipId }, header: await mutationHeaders() },
        body: { confirm: true },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      message.success('已撤销该交付单元的卡密和客户访问');
      setRevokeModalOpen(false);
      await Promise.all([deliveryDetail.refetch(), deliveryList.refetch()]);
    },
  });
  const active = tab === 'workspaces' ? all : tab === 'attention' ? attention : tab === 'deliveries' ? deliveryList : audit;
  const handle = (id: string) => navigate(`/?step=1&workspace=${encodeURIComponent(id)}`);
  // Records intentionally routes into the Workbench evidence action instead of
  // issuing a GET-only refresh or a blind Join retry from this page.
  const handleJoin = (batchId: string) => navigate(`/?step=4&batch=${encodeURIComponent(batchId)}&refresh=1`);
  const handleRemoval = (batchId: string) => navigate(`/?step=6&batch=${encodeURIComponent(batchId)}`);
  const pageTable = (data: typeof all.data | undefined) => <ProjectionTable
    items={data?.items ?? []}
    page={data?.page ?? page}
    pageSize={data?.pageSize ?? pageSize}
    total={data?.total ?? 0}
    onPage={(nextPage, nextSize) => updateParams({ page: String(nextPage), page_size: String(nextSize) })}
    onHandle={handle}
  />;
  return (
    <OwnerShell>
      <Typography.Title level={2}>记录与问题</Typography.Title>
      <Alert type="info" showIcon title="这里仅显示已保存的当前结论；打开页面不会读取平台或创建操作。" />
      {tab === 'workspaces' && <Space className="records-filters"><Typography.Text>运营结论</Typography.Text><Select
        allowClear
        aria-label="按运营结论筛选"
        value={state}
        placeholder="全部结论"
        onChange={(value) => updateParams({ operational_state: value, page: '1' })}
        options={[{ value: 'unknown', label: '证据不足' }, { value: 'operational', label: '当前可运营' }, { value: 'deactivated', label: '已停用' }, { value: 'not_found', label: '团队空间不存在' }]}
      /></Space>}
      {tab === 'audit' && <Space className="records-filters" wrap>
        <Select allowClear aria-label="按操作者筛选" value={auditActor} placeholder="全部操作者" onChange={(value) => updateParams({ audit_actor: value, page: '1' })} options={[{ value: 'owner', label: '系统所有者' }, { value: 'system', label: '系统' }, { value: 'anonymous', label: '客户' }]} />
        <Select allowClear aria-label="按结果筛选" value={auditOutcome} placeholder="全部结果" onChange={(value) => updateParams({ audit_outcome: value, page: '1' })} options={[{ value: 'succeeded', label: '成功' }, { value: 'failed', label: '失败' }, { value: 'denied', label: '拒绝' }]} />
        <Select allowClear aria-label="按事件筛选" value={auditEventType} placeholder="全部事件" onChange={(value) => updateParams({ audit_event_type: value, page: '1' })} options={[{ value: 'owner.audit_exported', label: '操作记录导出' }, { value: 'retention.cleanup_completed', label: '保留清理' }, { value: 'batch.service_ended', label: '批次服务结束' }, { value: 'owner.card_revoked', label: '卡密撤销' }]} />
        <Input allowClear aria-label="按关联链筛选" value={auditCorrelationId} placeholder="关联链" onChange={(event) => updateParams({ audit_correlation_id: event.target.value || undefined, page: '1' })} />
      </Space>}
      <Tabs
        activeKey={tab}
        renderTabBar={(props, DefaultTabBar) => <DefaultTabBar {...props} mobile />}
        onChange={(next: string) => updateParams({ tab: next, page: '1', operational_state: undefined })}
        items={[
          {
            key: 'workspaces',
            label: '团队空间与批次',
            children: all.isLoading ? <Spin /> : all.isError ? <Alert type="error" showIcon title="无法载入记录" action={<Button onClick={() => void all.refetch()}>重试</Button>} /> : pageTable(all.data),
          },
          {
            key: 'attention',
            label: '需要处理',
            children: attention.isLoading || joinAttention.isLoading || removalAttention.isLoading ? <Spin /> : attention.isError || joinAttention.isError || removalAttention.isError ? <Alert type="error" showIcon title="无法载入待处理事项" action={<Button onClick={() => { void attention.refetch(); void joinAttention.refetch(); void removalAttention.refetch(); }}>重试</Button>} /> : <Space orientation="vertical" size="large" className="full-width"><RemovalAttentionTable items={removalAttention.data?.items ?? []} onHandle={handleRemoval} /><JoinAttentionTable items={joinAttention.data?.items ?? []} onHandle={handleJoin} onReconcile={handleJoin} loading={false} />{pageTable(attention.data)}</Space>,
          },
          {
            key: 'audit',
            label: '操作记录',
            children: audit.isLoading ? <Spin /> : audit.isError ? <Alert type="error" showIcon title="无法载入操作记录" action={<Button onClick={() => void audit.refetch()}>重试</Button>} /> : <>
              <Space className="records-filters">
                <Button icon={<DownloadOutlined />} onClick={() => { window.location.href = auditExportURL('json'); }}>导出 JSON</Button>
                <Button icon={<DownloadOutlined />} onClick={() => { window.location.href = auditExportURL('csv'); }}>导出 CSV</Button>
              </Space>
              <AuditTable data={audit.data} page={page} pageSize={pageSize} onPage={(nextPage, nextSize) => updateParams({ page: String(nextPage), page_size: String(nextSize) })} />
            </>,
          },
          {
            key: 'deliveries',
            label: '客户交付',
            children: deliveryList.isLoading ? <Spin /> : deliveryList.isError ? <Alert type="error" showIcon title="无法载入客户交付" action={<Button onClick={() => void deliveryList.refetch()}>重试</Button>} /> : (
              <>
                <Space className="records-filters" wrap>
                  <Select
                    aria-label="按服务状态筛选"
                    allowClear
                    value={serviceStatus}
                    placeholder="全部服务状态"
                    onChange={(value) => updateParams({ service_status: value, page: '1' })}
                    options={[{ value: 'active', label: '服务中' }, { value: 'ended', label: '服务已结束' }]}
                  />
                  <Select
                    aria-label="按卡密状态筛选"
                    allowClear
                    value={cardStatus}
                    placeholder="全部卡密状态"
                    onChange={(value) => updateParams({ card_status: value, page: '1' })}
                    options={[{ value: 'unactivated', label: '未激活' }, { value: 'active', label: '有效' }, { value: 'revoked', label: '已撤销' }]}
                  />
                  <Select
                    aria-label="按订单状态筛选"
                    allowClear
                    value={orderStatus}
                    placeholder="全部订单状态"
                    onChange={(value) => updateParams({ order_status: value, page: '1' })}
                    options={[{ value: 'unclaimed', label: '未兑换' }, { value: 'claimed', label: '已兑换' }]}
                  />
                </Space>
                <Table<DeliveryRecord>
                  rowKey="membershipId"
                  size="small"
                  scroll={{ x: 1160 }}
                  pagination={{ current: deliveryList.data?.page ?? page, pageSize: deliveryList.data?.pageSize ?? pageSize, total: deliveryList.data?.total ?? 0, showSizeChanger: true }}
                  onChange={(pagination) => updateParams({ page: String(pagination.current ?? 1), page_size: String(pagination.pageSize ?? 20) })}
                  dataSource={deliveryList.data?.items ?? []}
                  columns={[
                    { title: '团队空间', dataIndex: 'workspaceName', key: 'workspace' },
                    { title: '服务', dataIndex: 'serviceStatus', key: 'service', render: (value) => value === 'active' ? '服务中' : '已结束' },
                    { title: '卡密', dataIndex: 'cardStatus', key: 'card', render: (value) => value === 'active' ? '有效' : value === 'revoked' ? '已撤销' : '未激活' },
                    { title: '订单', dataIndex: 'orderStatus', key: 'order', render: (value) => value === 'claimed' ? '已兑换' : '未兑换' },
                    { title: '交付状态', dataIndex: 'assetStatus', key: 'asset' },
                    { title: '凭据状态', key: 'liveness', render: (_, item) => item.livenessStatus ?? '尚未检查' },
                    { title: '找回状态', key: 'reclaim', render: (_, item) => item.reclaimStatus ? `${item.reclaimStatus}${item.reclaimTier ? ` · ${item.reclaimTier}` : ''}` : '未请求' },
                    { title: '探测时间', key: 'probed', render: (_, item) => item.probedAt ? new Date(item.probedAt).toLocaleString() : '尚未完成' },
                    { title: '详情', key: 'detail', render: (_, item) => <Button size="small" onClick={() => setDeliveryMembershipID(item.membershipId)}>查看时间线</Button> },
                  ]}
                />
              </>
            ),
          },
        ]}
      />
      {active.isFetching && !active.isLoading && <Typography.Text type="secondary">正在更新已保存记录…</Typography.Text>}
      <Drawer title="客户交付时间线" open={Boolean(deliveryMembershipID)} onClose={() => { setDeliveryMembershipID(undefined); setRevokeModalOpen(false); }} size={720}>
        {deliveryDetail.isLoading ? <Spin /> : deliveryDetail.isError ? <Alert type="error" showIcon title="无法载入交付详情" action={<Button onClick={() => void deliveryDetail.refetch()}>重试</Button>} /> : deliveryDetail.data ? (
          <Space orientation="vertical" size="large" className="full-width">
            <Descriptions
              bordered
              size="small"
              column={1}
              items={[
                { key: 'workspace', label: '团队空间', children: deliveryDetail.data.workspaceName },
                { key: 'service', label: '服务状态', children: deliveryDetail.data.serviceStatus === 'active' ? '服务中' : '已结束' },
                { key: 'card', label: '卡密状态', children: deliveryDetail.data.cardStatus === 'active' ? `有效 · 尾号 ${deliveryDetail.data.cardDisplaySuffix ?? ''}` : deliveryDetail.data.cardStatus === 'revoked' ? '已撤销' : '未激活' },
                { key: 'order', label: '订单状态', children: deliveryDetail.data.orderStatus === 'claimed' ? '已兑换' : '未兑换' },
                { key: 'asset', label: '交付状态', children: deliveryDetail.data.assetStatus },
                { key: 'liveness', label: '凭据状态', children: deliveryDetail.data.livenessStatus ?? '尚未检查' },
                { key: 'origin', label: '最近来源', children: deliveryDetail.data.livenessOrigin ?? '尚未记录' },
                { key: 'probe', label: '最近探测', children: deliveryDetail.data.probedAt ? `${new Date(deliveryDetail.data.probedAt).toLocaleString()}${deliveryDetail.data.livenessHttpStatus ? ` · HTTP ${deliveryDetail.data.livenessHttpStatus}` : ''}` : '尚未记录' },
                { key: 'reclaim', label: '找回层级', children: deliveryDetail.data.reclaimTier ?? '尚未请求' },
              ]}
            />
            {deliveryDetail.data.assetStatus === 'unavailable' && deliveryDetail.data.reclaimResult === 'unrecoverable' && (
              <Popconfirm
                title="确认授权重新找回？"
                okText="授权找回"
                cancelText="取消"
                onConfirm={() => deliveryReclaim.mutate(deliveryDetail.data!.membershipId)}
              >
                <Button icon={<RedoOutlined />} loading={deliveryReclaim.isPending}>授权重新找回</Button>
              </Popconfirm>
            )}
            {deliveryReclaim.isError && <Alert type="error" showIcon title={deliveryReclaim.error.message} />}
            {deliveryDetail.data.cardStatus === 'active' && <Button danger loading={deliveryCardRevoke.isPending} onClick={() => { deliveryCardRevoke.reset(); setRevokeModalOpen(true); }}>撤销卡密</Button>}
            <Table<DeliveryRecordEvent>
              rowKey={(item) => `${item.occurredAt}-${item.action}-${item.result}`}
              size="small"
              pagination={false}
              dataSource={deliveryDetail.data.timeline ?? []}
              scroll={{ x: 620 }}
              columns={[
                { title: '时间', key: 'time', render: (_, item) => new Date(item.occurredAt).toLocaleString() },
                { title: '动作', dataIndex: 'action', key: 'action' },
                { title: '结果', dataIndex: 'result', key: 'result' },
                { title: '来源', key: 'origin', render: (_, item) => item.origin ?? '系统记录' },
                { title: 'HTTP', key: 'http', render: (_, item) => item.httpStatus ?? '未提供' },
                { title: '原因', key: 'reason', render: (_, item) => item.reason ?? '未提供' },
              ]}
            />
          </Space>
        ) : <Empty description="尚无交付详情" />}
      </Drawer>
      <Modal
        title="确认撤销该交付单元的卡密？"
        open={revokeModalOpen}
        okText="撤销卡密"
        cancelText="取消"
        okButtonProps={{ danger: true }}
        cancelButtonProps={{ disabled: deliveryCardRevoke.isPending }}
        confirmLoading={deliveryCardRevoke.isPending}
        onCancel={() => { if (!deliveryCardRevoke.isPending) setRevokeModalOpen(false); }}
        onOk={() => { if (deliveryMembershipID) deliveryCardRevoke.mutate(deliveryMembershipID); }}
      >
        {deliveryDetail.data && (
          <Space orientation="vertical" size="middle" className="full-width">
            <Descriptions
              bordered
              size="small"
              column={1}
              items={[
                { key: 'workspace', label: '团队空间', children: deliveryDetail.data.workspaceName },
                { key: 'card', label: '卡密', children: deliveryDetail.data.cardDisplaySuffix ? `尾号 ${deliveryDetail.data.cardDisplaySuffix}` : '卡密' },
                { key: 'service', label: '服务状态', children: deliveryDetail.data.serviceStatus === 'active' ? '服务中' : '已结束' },
                { key: 'order', label: '订单状态', children: deliveryDetail.data.orderStatus === 'claimed' ? '已兑换' : '未兑换' },
              ]}
            />
            <Alert
              type="warning"
              showIcon
              title="仅撤销这个交付单元的客户访问"
              description="提交后首次兑换、原订单恢复、找回、令牌重签和已有令牌访问都会被拒绝。订单历史、批次成员关系和席位服务不会删除或结束；已保存在 TeamSeatWatch 外的 OAuth 副本不能远程抹除。"
            />
            {deliveryCardRevoke.isError && <Alert type="error" showIcon title={deliveryCardRevoke.error.message} />}
          </Space>
        )}
      </Modal>
    </OwnerShell>
  );
}
