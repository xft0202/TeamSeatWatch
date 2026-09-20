import {
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  LinkOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Input,
  Select,
  Space,
  Spin,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd';
import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import type { components } from '../generated/owner';
import { mutationHeaders, ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure, problem } from './problems';

type Workspace = components['schemas']['Workspace'];
type WorkspaceDetail = components['schemas']['WorkspaceDetail'];
type WorkspaceObservation = components['schemas']['WorkspaceObservation'];
type WorkspaceMember = components['schemas']['WorkspaceMember'];
type Account = components['schemas']['MotherAccount'];

const steps = [
  '连接团队空间',
  '导入成员账号',
  '安排本批成员',
  '确认加入团队',
  '生成客户卡密',
  '到期移除成员',
];

function statusTag(workspace: Workspace) {
  switch (workspace.operationalState) {
    case 'operational':
      return <Tag icon={<CheckCircleOutlined />} color="success">当前可运营</Tag>;
    case 'deactivated':
      return <Tag icon={<ExclamationCircleOutlined />} color="error">已停用</Tag>;
    case 'not_found':
      return <Tag icon={<ExclamationCircleOutlined />} color="warning">团队空间不存在</Tag>;
    default:
      return <Tag icon={<ExclamationCircleOutlined />}>证据不足</Tag>;
  }
}

function outcomeLabel(value: string) {
  const labels: Record<string, string> = {
    operational: '可运营',
    deactivated_workspace: '已停用',
    workspace_not_found: '团队空间不存在',
    manual_deactivated: '人工确认停用',
    manual_recovered: '人工确认恢复',
    manual_expiration_corrected: '人工修正到期时间',
    incomplete: '结果不完整',
    unauthorized: '认证失败',
    forbidden: '无访问权限',
    rate_limited: '平台限流',
    server_error: '平台服务错误',
    timeout: '读取超时',
    network_error: '网络错误',
  };
  return labels[value] ?? value;
}

function MutationAlert({ error, onRetry }: { error: unknown; onRetry?: (() => void) | undefined }) {
  if (!error) return null;
  const failure = problem(error);
  const description = failure.status === 401
    ? '登录已失效，请重新登录后再试。'
    : failure.status === 409 || failure.status === 412
      ? '保存的记录已经变化，请刷新后重试。'
      : '输入内容已保留，请检查后重试。';
  return <Alert type="error" showIcon title="操作未完成" description={description} action={onRetry ? <Button onClick={onRetry}>重试</Button> : undefined} />;
}

function WorkspaceDetailPanel({ detail, onManual, onObservationPage, onMemberPage }: {
  detail: WorkspaceDetail;
  onManual: () => void;
  onObservationPage: (page: number, pageSize: number) => void;
  onMemberPage: (page: number, pageSize: number) => void;
}) {
  const snapshotCompleteness = {
    complete: '完整', partial: '部分结果', unknown: '证据不足',
  }[detail.snapshotCompleteness] ?? detail.snapshotCompleteness;
  return (
    <Tabs
      renderTabBar={(props, DefaultTabBar) => <DefaultTabBar {...props} mobile />}
      items={[
        {
          key: 'summary',
          label: '当前结论',
          children: (
            <Space orientation="vertical" size="large" className="full-width">
              <Descriptions
                bordered
                size="small"
                column={1}
                items={[
                  { key: 'name', label: '团队空间', children: detail.workspace.displayName },
                  { key: 'binding', label: '管理员账号关系', children: detail.binding ? `${detail.binding.motherAccountName} · ${new Date(detail.binding.startedAt).toLocaleString()}` : '尚未建立关系' },
                  { key: 'state', label: '运营结论', children: statusTag(detail.workspace) },
                  { key: 'expiry', label: '当前采用到期时间', children: detail.workspace.activeUntil ? new Date(detail.workspace.activeUntil).toLocaleString() : '证据不足' },
                  { key: 'platform-expiry', label: '平台原始到期事实', children: detail.platformActiveUntil ? new Date(detail.platformActiveUntil).toLocaleString() : '证据不足' },
                  { key: 'manual-expiry', label: '人工到期修正', children: detail.manualActiveUntil ? new Date(detail.manualActiveUntil).toLocaleString() : '尚未记录' },
                  { key: 'manual', label: '人工运营核验', children: detail.manualConclusion && detail.manualObservedAt ? `${outcomeLabel(detail.manualConclusion)} · ${detail.manualSource ?? '人工来源'} · ${new Date(detail.manualObservedAt).toLocaleString()} · 有效至 ${detail.manualExpiresAt ? new Date(detail.manualExpiresAt).toLocaleString() : '证据不足'}` : '尚未记录' },
                  { key: 'members', label: '成员快照', children: `${detail.workspace.memberCount ?? '证据不足'} · ${snapshotCompleteness}` },
                  { key: 'pending', label: '待邀请', children: detail.workspace.pendingInviteCount ?? '证据不足' },
                  { key: 'evidence', label: '当前证据期限', children: detail.workspace.evidenceExpiresAt ? new Date(detail.workspace.evidenceExpiresAt).toLocaleString() : '证据不足' },
                ]}
              />
              <Button onClick={onManual}>人工核验</Button>
            </Space>
          ),
        },
        {
          key: 'observations',
          label: `观察事实 ${detail.observationTotal}`,
          children: detail.observations.length === 0 ? <Empty description="尚无观察事实" /> : (
            <Table<WorkspaceObservation>
              size="small"
              pagination={{ current: detail.observationPage, pageSize: detail.observationPageSize, total: detail.observationTotal, showSizeChanger: true }}
              onChange={(pagination) => onObservationPage(pagination.current ?? 1, pagination.pageSize ?? 20)}
              rowKey={(item) => `${item.type}:${item.sourceKind}:${item.observedAt}:${item.outcomeCode}`}
              dataSource={detail.observations}
              scroll={{ x: 760 }}
              columns={[
                { title: '事实类型', dataIndex: 'type', key: 'type' },
                { title: '来源', key: 'source', render: (_, item) => item.sourceKind === 'owner' ? '人工核验' : '平台读取' },
                { title: '端点', dataIndex: 'sourceEndpoint', key: 'endpoint' },
                { title: '结果', key: 'outcome', render: (_, item) => outcomeLabel(item.outcomeCode) },
                { title: '观察时间', key: 'observed', render: (_, item) => new Date(item.observedAt).toLocaleString() },
                { title: '证据期限', key: 'expires', render: (_, item) => new Date(item.expiresAt).toLocaleString() },
              ]}
            />
          ),
        },
        {
          key: 'members',
          label: `成员快照 ${detail.memberTotal}`,
          children: (
            <Space orientation="vertical" size="middle" className="full-width">
              <Descriptions
                size="small"
                column={1}
                items={[
                  { key: 'completeness', label: '完整性', children: snapshotCompleteness },
                  { key: 'source', label: '来源', children: detail.snapshotSourceEndpoint ?? '证据不足' },
                  { key: 'observed', label: '观察时间', children: detail.snapshotObservedAt ? new Date(detail.snapshotObservedAt).toLocaleString() : '证据不足' },
                  { key: 'expires', label: '证据期限', children: detail.snapshotExpiresAt ? new Date(detail.snapshotExpiresAt).toLocaleString() : '证据不足' },
                ]}
              />
              {detail.members.length === 0 ? <Empty description="尚无成员快照条目" /> : (
                <Table<WorkspaceMember>
                  size="small"
                  pagination={{ current: detail.memberPage, pageSize: detail.memberPageSize, total: detail.memberTotal, showSizeChanger: true }}
                  onChange={(pagination) => onMemberPage(pagination.current ?? 1, pagination.pageSize ?? 20)}
                  rowKey={(item) => `${item.kind}:${item.identifier}`}
                  dataSource={detail.members}
                  scroll={{ x: 560 }}
                  columns={[
                    { title: '类型', dataIndex: 'kind', key: 'kind' },
                    { title: '标识', dataIndex: 'identifier', key: 'identifier' },
                    { title: '状态', dataIndex: 'status', key: 'status' },
                    { title: '角色', dataIndex: 'role', key: 'role', render: (value?: string) => value ?? '未提供' },
                  ]}
                />
              )}
            </Space>
          ),
        },
      ]}
    />
  );
}

export default function WorkbenchPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const requested = Number(params.get('step') ?? '1');
  const activeStep = Number.isInteger(requested) && requested >= 1 && requested <= 6
    ? String(requested) : '1';
  const pageValue = (name: string, fallback: number, maximum?: number) => {
    const value = Number(params.get(name) ?? fallback);
    return Number.isInteger(value) && value >= 1 && (maximum === undefined || value <= maximum) ? value : fallback;
  };
  const workspacePage = pageValue('page', 1);
  const workspacePageSize = pageValue('page_size', 20, 100);
  const observationPage = pageValue('observation_page', 1);
  const observationPageSize = pageValue('observation_page_size', 20, 100);
  const memberPage = pageValue('member_page', 1);
  const memberPageSize = pageValue('member_page_size', 20, 100);
  const updateParams = (updates: Record<string, string | undefined>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined) next.delete(key); else next.set(key, value);
    }
    setParams(next);
  };
  const [selected, setSelected] = useState<Workspace>();
  const [drawer, setDrawer] = useState<'detail' | 'account' | 'workspace' | 'binding' | 'manual'>();
  const [activeRead, setActiveRead] = useState<string>();
  const [activeReadWorkspace, setActiveReadWorkspace] = useState<string>();
  const selectedWorkspaceID = selected?.id ?? params.get('workspace') ?? undefined;

  const workspaces = useQuery({
    queryKey: ['workspaces', workspacePage, workspacePageSize],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/workspaces', {
        params: { query: { page: workspacePage, page_size: workspacePageSize, sort: 'updated_desc' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const accounts = useQuery({
    queryKey: ['mother-accounts'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/mother-accounts', {
        params: { query: { page: 1, page_size: 100, sort: 'name_asc' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data.items;
    },
  });
  const detail = useQuery<WorkspaceDetail>({
    queryKey: ['workspace-detail', selectedWorkspaceID, observationPage, observationPageSize, memberPage, memberPageSize],
    enabled: Boolean(selectedWorkspaceID && (drawer === 'detail' || drawer === 'manual')),
    queryFn: async () => {
      if (!selectedWorkspaceID) throw new Error('Workspace selection is required');
      const response = await ownerApi.GET('/api/owner/v1/workspaces/{workspaceId}', {
        params: { path: { workspaceId: selectedWorkspaceID }, query: { observation_page: observationPage, observation_page_size: observationPageSize, member_page: memberPage, member_page_size: memberPageSize } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const readStatus = useQuery({
    queryKey: ['workspace-read', activeRead],
    enabled: Boolean(activeRead),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'queued' || status === 'running' || status === 'retry_wait' ? 2000 : false;
    },
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/workspace-reads/{readId}', {
        params: { path: { readId: activeRead ?? '' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  useEffect(() => {
    if (problem(workspaces.error).status === 401) navigate('/login', { replace: true, state: { expired: true } });
  }, [navigate, workspaces.error]);
  useEffect(() => {
    const workspaceID = params.get('workspace');
    if (!workspaceID || drawer) return;
    const item = workspaces.data?.items.find((workspace) => workspace.id === workspaceID);
    if (item) setSelected(item);
    setDrawer('detail');
  }, [drawer, params, workspaces.data?.items]);
  useEffect(() => {
    if (readStatus.data?.status === 'succeeded') {
      void queryClient.invalidateQueries({ queryKey: ['workspaces'] });
      void queryClient.invalidateQueries({ queryKey: ['workspace-detail', selectedWorkspaceID] });
    }
  }, [queryClient, readStatus.data?.status, selectedWorkspaceID]);

  const createAccount = useMutation({
    mutationFn: async (values: {
      displayName: string;
      loginIdentifier: string;
      password: string;
      platformAccountRef: string;
    }) => {
      const response = await ownerApi.POST('/api/owner/v1/mother-accounts', {
        params: { header: await mutationHeaders() },
        body: values,
      });
      if (response.error) throw apiFailure(response.error, response.response.status);
    },
    onSuccess: async () => {
      setDrawer(undefined);
      await queryClient.invalidateQueries({ queryKey: ['mother-accounts'] });
      message.success('管理员账号已保存');
    },
  });
  const createWorkspace = useMutation({
    mutationFn: async (values: { displayName: string; platformWorkspaceId: string }) => {
      const response = await ownerApi.POST('/api/owner/v1/workspaces', {
        params: { header: await mutationHeaders() },
        body: values,
      });
      if (response.error) throw apiFailure(response.error, response.response.status);
    },
    onSuccess: async () => {
      setDrawer(undefined);
      await queryClient.invalidateQueries({ queryKey: ['workspaces'] });
      message.success('团队空间已保存');
    },
  });
  const createBinding = useMutation({
    mutationFn: async (values: { motherAccountId: string; workspaceId: string }) => {
      const response = await ownerApi.POST('/api/owner/v1/bindings', {
        params: { header: await mutationHeaders() },
        body: values,
      });
      if (response.error) throw apiFailure(response.error, response.response.status);
    },
    onSuccess: () => {
      setDrawer(undefined);
      message.success('管理员账号与团队空间已连接');
    },
  });
  const refresh = useMutation({
    mutationFn: async (workspaceId: string) => {
      const response = await ownerApi.POST('/api/owner/v1/workspaces/{workspaceId}/refresh', {
        params: { path: { workspaceId }, header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID() },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: (result, workspaceId) => {
      setActiveRead(result.id);
      setActiveReadWorkspace(workspaceId);
    },
  });
  const manual = useMutation({
    mutationFn: async (values: { conclusion: 'deactivated' | 'recovered' | 'expiration_corrected'; source: string; activeUntil?: string }) => {
      if (!selectedWorkspaceID) throw new Error('Workspace selection is required');
      const response = await ownerApi.POST('/api/owner/v1/workspaces/{workspaceId}/manual-verification', {
        params: { path: { workspaceId: selectedWorkspaceID }, header: await mutationHeaders() },
        body: { conclusion: values.conclusion, source: values.source as 'platform_ui' | 'platform_subscription_page', observedAt: new Date().toISOString(), ...(values.activeUntil ? { activeUntil: new Date(values.activeUntil).toISOString() } : {}) },
      });
      if (response.error) throw apiFailure(response.error, response.response.status);
    },
    onSuccess: async () => {
      setDrawer('detail');
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['workspaces'] }),
        queryClient.invalidateQueries({ queryKey: ['workspace-detail', selectedWorkspaceID] }),
      ]);
      message.success('人工核验已记录');
    },
  });

  const firstStep = (
    <div className="workflow-step">
      <Alert
        type="info"
        showIcon
        title="本步要完成什么"
        description="建立管理员账号与团队空间（Workspace）的关系，读取最新事实，并确认当前证据足以继续。"
      />
      {readStatus.isFetching && <Alert type="info" showIcon title="正在读取最新事实" />}
      {(readStatus.data?.status === 'failed' || readStatus.data?.status === 'interrupted') && (
        <Alert
          type="warning"
          showIcon
          title={readStatus.data.status === 'interrupted' ? '读取已中止，当前事实没有更新' : '读取未完成，当前仍为证据不足'}
          action={activeReadWorkspace ? <Button onClick={() => refresh.mutate(activeReadWorkspace)}>重新读取</Button> : undefined}
        />
      )}
      <MutationAlert error={refresh.error} onRetry={typeof refresh.variables === 'string' ? () => refresh.mutate(refresh.variables) : undefined} />
      <div className="section-heading">
        <Typography.Title level={3}>团队空间</Typography.Title>
        <Space wrap>
          <Button onClick={() => setDrawer('account')}>添加管理员账号</Button>
          <Button onClick={() => setDrawer('workspace')}>添加团队空间</Button>
          <Button icon={<LinkOutlined />} onClick={() => setDrawer('binding')}>建立关系</Button>
        </Space>
      </div>
      {workspaces.isLoading ? <Spin /> : workspaces.isError ? (
        <Alert
          type="error"
          showIcon
          title="无法载入团队空间"
          action={<Button onClick={() => void workspaces.refetch()}>重试</Button>}
        />
      ) : (workspaces.data?.items.length ?? 0) === 0 ? (
        <Empty description="还没有团队空间。先添加管理员账号和团队空间，再建立关系。" />
      ) : (
        <Table<Workspace>
          size="small"
          rowKey="id"
          pagination={{ current: workspaces.data?.page ?? workspacePage, pageSize: workspaces.data?.pageSize ?? workspacePageSize, total: workspaces.data?.total ?? 0, showSizeChanger: true }}
          onChange={(pagination) => updateParams({ page: String(pagination.current ?? 1), page_size: String(pagination.pageSize ?? 20) })}
          dataSource={workspaces.data?.items ?? []}
          scroll={{ x: 760 }}
          columns={[
            { title: '团队空间', dataIndex: 'displayName', key: 'name', fixed: 'left' },
            { title: '运营结论', key: 'state', render: (_, item) => statusTag(item) },
            {
              title: '当前采用到期时间',
              key: 'expiry',
              render: (_, item) => item.activeUntil
                ? new Date(item.activeUntil).toLocaleString() : '尚未读取',
            },
            {
              title: '席位',
              key: 'seats',
              render: (_, item) => item.seatLimit === undefined
                ? '证据不足' : `${item.memberCount ?? 0} / ${item.seatLimit}`,
            },
            {
              title: '观察时间',
              dataIndex: 'updatedAt',
              key: 'updated',
              render: (value: string) => new Date(value).toLocaleString(),
            },
            {
              title: '操作',
              key: 'actions',
              fixed: 'right',
              render: (_, item) => (
                <Space>
                  <Button
                    size="small"
                    onClick={() => { setSelected(item); updateParams({ workspace: item.id }); setDrawer('detail'); }}
                  >
                    查看
                  </Button>
                  <Button
                    size="small"
                    icon={<ReloadOutlined />}
                    loading={refresh.isPending && refresh.variables === item.id}
                    onClick={() => refresh.mutate(item.id)}
                  >
                    读取最新事实
                  </Button>
                </Space>
              ),
            },
          ]}
        />
      )}
      <Alert
        type="warning"
        showIcon
        title="下一步"
        description="只有当前证据明确可运营后，才能前往第 2 步导入成员账号。"
      />
    </div>
  );

  return (
    <OwnerShell workspace={detail.data?.workspace ?? selected}>
      <Typography.Title level={2}>开始操作</Typography.Title>
      <Tabs
        activeKey={activeStep}
        onChange={(step) => updateParams({ step })}
        className="workflow-tabs"
        renderTabBar={(props, DefaultTabBar) => <DefaultTabBar {...props} mobile />}
        items={steps.map((label, index) => ({
          key: String(index + 1),
          label: `${index + 1}. ${label}`,
          disabled: index > 0,
          children: index === 0 ? firstStep : (
            <Alert
              type="info"
              showIcon
              title="还不能进入这一步"
              description={`请先返回第 ${index} 步完成前置事项。`}
            />
          ),
        }))}
      />

      <Drawer title="团队空间事实" open={drawer === 'detail'} onClose={() => { setDrawer(undefined); updateParams({ workspace: undefined, observation_page: undefined, observation_page_size: undefined, member_page: undefined, member_page_size: undefined }); }} size={640}>
        {detail.isLoading && <Spin />}
        {detail.isError && <Alert type="error" showIcon title="无法载入团队空间事实" action={<Button onClick={() => void detail.refetch()}>重试</Button>} />}
        {detail.data && <WorkspaceDetailPanel
          detail={detail.data}
          onManual={() => setDrawer('manual')}
          onObservationPage={(page, pageSize) => updateParams({ observation_page: String(page), observation_page_size: String(pageSize) })}
          onMemberPage={(page, pageSize) => updateParams({ member_page: String(page), member_page_size: String(pageSize) })}
        />}
      </Drawer>
      <Drawer title="添加管理员账号" open={drawer === 'account'} onClose={() => setDrawer(undefined)} size={480}>
        <MutationAlert error={createAccount.error} onRetry={createAccount.variables ? () => createAccount.mutate(createAccount.variables) : undefined} />
        <Form layout="vertical" onFinish={(values) => createAccount.mutate(values)}>
          <Form.Item name="displayName" label="显示名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="platformAccountRef" label="平台账号引用"><Input /></Form.Item>
          <Form.Item name="loginIdentifier" label="登录标识" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="password" label="平台密码" rules={[{ required: true }]}><Input.Password /></Form.Item>
          <Button type="primary" htmlType="submit" loading={createAccount.isPending}>保存管理员账号</Button>
        </Form>
      </Drawer>
      <Drawer title="添加团队空间" open={drawer === 'workspace'} onClose={() => setDrawer(undefined)} size={480}>
        <MutationAlert error={createWorkspace.error} onRetry={createWorkspace.variables ? () => createWorkspace.mutate(createWorkspace.variables) : undefined} />
        <Form layout="vertical" onFinish={(values) => createWorkspace.mutate(values)}>
          <Form.Item name="displayName" label="显示名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="platformWorkspaceId" label="平台团队空间标识" rules={[{ required: true }]}><Input /></Form.Item>
          <Button type="primary" htmlType="submit" loading={createWorkspace.isPending}>保存团队空间</Button>
        </Form>
      </Drawer>
      <Drawer title="建立管理员账号关系" open={drawer === 'binding'} onClose={() => setDrawer(undefined)} size={480}>
        <MutationAlert error={createBinding.error} onRetry={createBinding.variables ? () => createBinding.mutate(createBinding.variables) : undefined} />
        <Form layout="vertical" onFinish={(values) => createBinding.mutate(values)}>
          <Form.Item name="motherAccountId" label="管理员账号" rules={[{ required: true }]}>
            <Select options={(accounts.data ?? []).map((item: Account) => ({ value: item.id, label: item.displayName }))} />
          </Form.Item>
          <Form.Item name="workspaceId" label="团队空间" rules={[{ required: true }]}>
            <Select options={(workspaces.data?.items ?? []).map((item) => ({ value: item.id, label: item.displayName }))} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={createBinding.isPending}>建立关系</Button>
        </Form>
      </Drawer>
      <Drawer title="人工核验" open={drawer === 'manual'} onClose={() => setDrawer('detail')} size={480}>
        <MutationAlert error={manual.error} onRetry={manual.variables ? () => manual.mutate(manual.variables) : undefined} />
        <Alert type="warning" showIcon title="请仅记录刚刚在平台界面完成的核验。" />
        <Form layout="vertical" className="drawer-form" onFinish={(values) => manual.mutate(values)}>
          <Form.Item name="conclusion" label="当前结论" rules={[{ required: true }]}>
            <Select options={[{ value: 'deactivated', label: '确认已停用' }, { value: 'recovered', label: '确认已恢复' }, { value: 'expiration_corrected', label: '修正到期时间' }]} />
          </Form.Item>
          <Form.Item name="activeUntil" label="修正后的到期时间" dependencies={['conclusion']} rules={[({ getFieldValue }) => ({ validator(_, value) { return getFieldValue('conclusion') === 'expiration_corrected' && !value ? Promise.reject(new Error('请选择到期时间')) : Promise.resolve(); } })]}>
            <Input type="datetime-local" />
          </Form.Item>
          <Form.Item name="source" label="核验来源" rules={[{ required: true }]}>
            <Select options={[{ value: 'platform_ui', label: '平台管理界面' }, { value: 'platform_subscription_page', label: '平台订阅页面' }]} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={manual.isPending}>记录人工核验</Button>
        </Form>
      </Drawer>
    </OwnerShell>
  );
}
