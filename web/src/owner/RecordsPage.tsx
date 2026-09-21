import { ExclamationCircleOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Empty, Select, Space, Spin, Table, Tabs, Tag, Typography } from 'antd';
import { useNavigate, useSearchParams } from 'react-router';
import type { components } from '../generated/owner';
import { ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure } from './problems';

type Workspace = components['schemas']['Workspace'];
type JoinOperation = components['schemas']['JoinOperation'];

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
  const tab = params.get('tab') === 'attention' ? 'attention' : 'workspaces';
  const parsedPage = Number(params.get('page') ?? '1');
  const parsedPageSize = Number(params.get('page_size') ?? '20');
  const page = Number.isInteger(parsedPage) && parsedPage >= 1 ? parsedPage : 1;
  const pageSize = Number.isInteger(parsedPageSize) && parsedPageSize >= 1 && parsedPageSize <= 100 ? parsedPageSize : 20;
  const requestedState = params.get('operational_state');
  const state: Workspace['operationalState'] | undefined = requestedState === 'unknown' || requestedState === 'operational' || requestedState === 'deactivated' || requestedState === 'not_found' ? requestedState : undefined;
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
  const active = tab === 'workspaces' ? all : attention;
  const handle = (id: string) => navigate(`/?step=1&workspace=${encodeURIComponent(id)}`);
  // Records intentionally routes into the Workbench evidence action instead of
  // issuing a GET-only refresh or a blind Join retry from this page.
  const handleJoin = (batchId: string) => navigate(`/?step=4&batch=${encodeURIComponent(batchId)}&refresh=1`);
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
            children: attention.isLoading || joinAttention.isLoading ? <Spin /> : attention.isError || joinAttention.isError ? <Alert type="error" showIcon title="无法载入或提交待处理事项" action={<Button onClick={() => { void attention.refetch(); void joinAttention.refetch(); }}>重试</Button>} /> : <Space orientation="vertical" size="large" className="full-width"><JoinAttentionTable items={joinAttention.data?.items ?? []} onHandle={handleJoin} onReconcile={handleJoin} loading={false} />{pageTable(attention.data)}</Space>,
          },
        ]}
      />
      {active.isFetching && !active.isLoading && <Typography.Text type="secondary">正在更新已保存记录…</Typography.Text>}
    </OwnerShell>
  );
}
