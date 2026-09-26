import { useQuery } from '@tanstack/react-query';
import { Button, Empty, Input, Select, Spin, Table, Tabs } from 'antd';
import { DownloadOutlined } from '@ant-design/icons';
import { useNavigate, useSearchParams } from 'react-router';
import type { components } from '../generated/owner';
import { ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure } from './problems';

type Workspace = components['schemas']['Workspace'];
type JoinOperation = components['schemas']['JoinOperation'];
type RemovalOperation = components['schemas']['RemovalOperation'];
type AuditEvent = components['schemas']['AuditEvent'];

// 记录页（规格书 §6）：第一层「还没处理完」与工作台同一事实推导（needs-attention 端点），
// 高风险动作不在这里执行——[去处理] 跳回工作台；第二层「处理记录」是脱敏审计，可导出。
// 客户交付数据在交付页。

function AuditTable({ data, page, pageSize, onPage }: {
  data: components['schemas']['AuditEventList'] | undefined;
  page: number;
  pageSize: number;
  onPage: (page: number, pageSize: number) => void;
}) {
  return (
    <Table<AuditEvent>
      rowKey={(item) => `${item.occurredAt}-${item.eventType}-${item.correlationId}`}
      size="small"
      pagination={{
        current: data?.page ?? page,
        pageSize: data?.pageSize ?? pageSize,
        total: data?.total ?? 0,
        showSizeChanger: true,
      }}
      onChange={(pagination) => onPage(pagination.current ?? 1, pagination.pageSize ?? 20)}
      dataSource={data?.items ?? []}
      columns={[
        {
          title: '时间',
          dataIndex: 'occurredAt',
          key: 'time',
          width: 170,
          render: (value: string) => (
            <span className="mono" style={{ fontSize: 12 }}>{new Date(value).toLocaleString()}</span>
          ),
        },
        { title: '操作者', dataIndex: 'actor', key: 'actor', width: 90 },
        { title: '事件', dataIndex: 'eventType', key: 'event' },
        { title: '结果', dataIndex: 'outcome', key: 'outcome', width: 90 },
        { title: '对象', dataIndex: 'entityType', key: 'entity', width: 120 },
      ]}
    />
  );
}

export default function RecordsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') === 'audit' ? 'audit' : 'attention';

  const parsedPage = Number(params.get('page') ?? '1');
  const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;
  const parsedPageSize = Number(params.get('page_size') ?? '20');
  const pageSize = Number.isInteger(parsedPageSize) && parsedPageSize >= 1 && parsedPageSize <= 100 ? parsedPageSize : 20;

  // 先取局部变量再收窄，让 TS 推导出字面量联合（exactOptionalPropertyTypes）
  const requestedActor = params.get('audit_actor');
  const auditActor: 'owner' | 'system' | 'anonymous' | undefined =
    requestedActor === 'owner' || requestedActor === 'system' || requestedActor === 'anonymous'
      ? requestedActor
      : undefined;
  const requestedOutcome = params.get('audit_outcome');
  const auditOutcome: 'succeeded' | 'failed' | 'denied' | undefined =
    requestedOutcome === 'succeeded' || requestedOutcome === 'failed' || requestedOutcome === 'denied'
      ? requestedOutcome
      : undefined;
  const auditEventType = params.get('audit_event_type') ?? undefined;
  const auditCorrelationId = params.get('audit_correlation_id') ?? undefined;

  function updateParams(updates: Record<string, string | undefined>) {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined) next.delete(key);
      else next.set(key, value);
    }
    setParams(next);
  }

  const attentionWorkspaces = useQuery({
    queryKey: ['workspaces', 'needs-attention', 'records'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/workspaces/needs-attention', {
        params: { query: { page: 1, page_size: 50 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const joinAttention = useQuery({
    queryKey: ['join-operations', 'needs-attention', 'records'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/join-operations/needs-attention', {
        params: { query: { page: 1, page_size: 50 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const removalAttention = useQuery({
    queryKey: ['removal-operations', 'needs-attention', 'records'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/removal-operations/needs-attention', {
        params: { query: { page: 1, page_size: 50 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const audit = useQuery({
    queryKey: ['audit-events', 'records', page, pageSize, auditActor, auditOutcome, auditEventType, auditCorrelationId],
    enabled: tab === 'audit',
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/audit-events', {
        params: {
          query: {
            page,
            page_size: pageSize,
            ...(auditActor ? { actor: auditActor } : {}),
            ...(auditOutcome ? { outcome: auditOutcome } : {}),
            ...(auditEventType ? { event_type: auditEventType } : {}),
            ...(auditCorrelationId ? { correlation_id: auditCorrelationId } : {}),
          },
        },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  // 高风险动作不在这里执行：全部跳回工作台的对应空间（规格书 §6）
  const goto = (workspaceId: string) => navigate(`/?workspace=${encodeURIComponent(workspaceId)}`);

  function auditExportURL(format: 'json' | 'csv') {
    const query = new URLSearchParams({ format });
    if (auditActor) query.set('actor', auditActor);
    if (auditOutcome) query.set('outcome', auditOutcome);
    if (auditEventType) query.set('event_type', auditEventType);
    if (auditCorrelationId) query.set('correlation_id', auditCorrelationId);
    return `/api/owner/v1/audit-events/export?${query.toString()}`;
  }

  const joinItems = joinAttention.data?.items ?? [];
  const removalItems = removalAttention.data?.items ?? [];
  const workspaceItems = attentionWorkspaces.data?.items ?? [];
  const openCount = joinItems.length + removalItems.length + workspaceItems.length;

  return (
    <OwnerShell fullBleed>
      <main className="page">
        <span className="micro">记录</span>
        <h1 className="page__title">记录</h1>

        <Tabs
          activeKey={tab}
          onChange={(next) => updateParams({ tab: next })}
          items={[
            {
              key: 'attention',
              label: `还没处理完 · ${openCount}`,
              children:
                joinAttention.isLoading || removalAttention.isLoading || attentionWorkspaces.isLoading ? (
                  <Spin />
                ) : joinAttention.isError || removalAttention.isError || attentionWorkspaces.isError ? (
                  <div className="quietnote">
                    读取失败：
                    {joinAttention.error instanceof Error ? joinAttention.error.message : ''}
                  </div>
                ) : openCount === 0 ? (
                  <Empty description="没有还没处理完的事" />
                ) : (
                  <>
                    {removalItems.length > 0 ? (
                      <Table<RemovalOperation>
                        size="small"
                        rowKey="id"
                        pagination={false}
                        style={{ marginBottom: 24 }}
                        dataSource={removalItems}
                        columns={[
                          { title: '范围', key: 'scope', width: 110, render: () => '到期移除' },
                          { title: '目标总数', dataIndex: 'targetTotal', key: 'target', width: 100 },
                          {
                            title: '结果',
                            key: 'result',
                            render: (_: unknown, item) =>
                              `${item.succeededCount} 已确认移除 / ${item.blockedCount} 待核对 / ${item.pendingCount} 进行中`,
                          },
                          {
                            title: '',
                            key: 'go',
                            width: 90,
                            render: (_: unknown, item) => (
                              <Button type="link" size="small" onClick={() => goto(item.workspaceId)}>
                                去处理
                              </Button>
                            ),
                          },
                        ]}
                      />
                    ) : null}

                    {joinItems.length > 0 ? (
                      <Table<JoinOperation>
                        size="small"
                        rowKey="id"
                        pagination={false}
                        style={{ marginBottom: 24 }}
                        dataSource={joinItems}
                        columns={[
                          { title: '范围', key: 'scope', width: 110, render: () => '确认加入' },
                          { title: '目标总数', dataIndex: 'targetTotal', key: 'target', width: 100 },
                          {
                            title: '结果',
                            key: 'result',
                            render: (_: unknown, item) =>
                              `${item.succeededCount} 已加入 / ${item.failedCount} 没加入 / ${item.blockedCount} 待核对 / ${item.pendingCount} 进行中`,
                          },
                          {
                            title: '',
                            key: 'go',
                            width: 90,
                            render: (_: unknown, item) => (
                              <Button type="link" size="small" onClick={() => goto(item.workspaceId)}>
                                去处理
                              </Button>
                            ),
                          },
                        ]}
                      />
                    ) : null}

                    {workspaceItems.length > 0 ? (
                      <Table<Workspace>
                        size="small"
                        rowKey="id"
                        pagination={false}
                        dataSource={workspaceItems}
                        columns={[
                          { title: '空间', dataIndex: 'displayName', key: 'name' },
                          {
                            title: '当前结论',
                            key: 'state',
                            width: 140,
                            render: (_: unknown, item: Workspace) =>
                              item.operationalState === 'deactivated'
                                ? '平台已停用'
                                : item.operationalState === 'not_found'
                                  ? '平台查不到'
                                  : item.operationalState === 'operational'
                                    ? '当前可运营'
                                    : '证据不足',
                          },
                          {
                            title: '到期时间',
                            key: 'active',
                            width: 170,
                            render: (_: unknown, item: Workspace) =>
                              item.activeUntil ? (
                                <span className="mono" style={{ fontSize: 12 }}>
                                  {new Date(item.activeUntil).toLocaleString()}
                                </span>
                              ) : (
                                '尚未读取'
                              ),
                          },
                          {
                            title: '',
                            key: 'go',
                            width: 90,
                            render: (_: unknown, item: Workspace) => (
                              <Button type="link" size="small" onClick={() => goto(item.id)}>
                                去处理
                              </Button>
                            ),
                          },
                        ]}
                      />
                    ) : null}
                  </>
                ),
            },
            {
              key: 'audit',
              label: '处理记录',
              children: (
                <>
                  <div className="toolbar">
                    <Select
                      aria-label="按操作者筛选"
                      allowClear
                      value={auditActor}
                      placeholder="全部操作者"
                      style={{ width: 130 }}
                      onChange={(value) => updateParams({ audit_actor: value })}
                      options={[
                        { value: 'owner', label: '系统所有者' },
                        { value: 'system', label: '系统' },
                        { value: 'anonymous', label: '客户' },
                      ]}
                    />
                    <Select
                      aria-label="按结果筛选"
                      allowClear
                      value={auditOutcome}
                      placeholder="全部结果"
                      style={{ width: 120 }}
                      onChange={(value) => updateParams({ audit_outcome: value })}
                      options={[
                        { value: 'succeeded', label: '成功' },
                        { value: 'failed', label: '失败' },
                        { value: 'denied', label: '拒绝' },
                      ]}
                    />
                    <Select
                      aria-label="按事件筛选"
                      allowClear
                      value={auditEventType}
                      placeholder="全部事件"
                      style={{ width: 150 }}
                      onChange={(value) => updateParams({ audit_event_type: value })}
                      options={[
                        { value: 'owner.audit_exported', label: '操作记录导出' },
                        { value: 'retention.cleanup_completed', label: '保留清理' },
                        { value: 'batch.service_ended', label: '批次服务结束' },
                        { value: 'owner.card_revoked', label: '卡密撤销' },
                      ]}
                    />
                    <Input
                      allowClear
                      aria-label="按关联链筛选"
                      value={auditCorrelationId}
                      placeholder="关联链"
                      style={{ width: 200 }}
                      onChange={(event) => updateParams({ audit_correlation_id: event.target.value || undefined })}
                    />
                    <span style={{ flex: 1 }} />
                    <Button
                      size="small"
                      icon={<DownloadOutlined />}
                      href={auditExportURL('json')}
                    >
                      导出 JSON
                    </Button>
                    <Button
                      size="small"
                      icon={<DownloadOutlined />}
                      href={auditExportURL('csv')}
                    >
                      导出 CSV
                    </Button>
                  </div>
                  {audit.isLoading ? (
                    <Spin />
                  ) : audit.isError ? (
                    <div className="quietnote">
                      读取失败：{audit.error instanceof Error ? audit.error.message : ''}
                    </div>
                  ) : (
                    <AuditTable
                      data={audit.data}
                      page={page}
                      pageSize={pageSize}
                      onPage={(nextPage, nextSize) => updateParams({ page: String(nextPage), page_size: String(nextSize) })}
                    />
                  )}
                </>
              ),
            },
          ]}
        />
      </main>
    </OwnerShell>
  );
}
