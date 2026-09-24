import {
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  LinkOutlined,
  UploadOutlined,
  SaveOutlined,
  PlayCircleOutlined,
  EditOutlined,
  FilterOutlined,
  ReloadOutlined,
  WarningOutlined,
  CopyOutlined,
  DownloadOutlined,
  KeyOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Alert,
  Button,
  DatePicker,
  Modal,
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
  Upload,
  message,
} from 'antd';
import { useEffect, useRef, useState } from 'react';
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
type TargetAccount = components['schemas']['TargetAccount'];
type TargetAccountDetail = components['schemas']['TargetAccountDetail'];
type Batch = components['schemas']['Batch'];
type BatchDetail = components['schemas']['BatchDetail'];
type BatchPreview = components['schemas']['BatchPreview'];
type JoinPreview = components['schemas']['JoinPreview'];
type JoinOperation = components['schemas']['JoinOperation'];
type JoinOperationTarget = components['schemas']['JoinOperationTarget'];
type RemovalPreview = components['schemas']['RemovalPreview'];
type RemovalOperation = components['schemas']['RemovalOperation'];
type RemovalOperationTarget = components['schemas']['RemovalOperationTarget'];
type DeliveryList = components['schemas']['DeliveryList'];
type Delivery = components['schemas']['Delivery'];
type PlannedAtValue = { toISOString: () => string };

function generateCardSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const encoded = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return `TSW1-${encoded}`;
}

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
  const targetPage = pageValue('target_page', 1);
  const targetPageSize = pageValue('target_page_size', 20, 100);
  const joinTargetPage = pageValue('join_target_page', 1);
  const joinTargetPageSize = pageValue('join_target_page_size', 20, 100);
  const targetSearch = params.get('target_search') ?? '';
  const targetStatus = params.get('target_status') ?? '';
  const targetProbeStatus = params.get('target_probe_status') ?? '';
  const targetSort = params.get('target_sort') ?? 'created_desc';
  const selectedBatchID = params.get('batch') ?? undefined;
  const updateParams = (updates: Record<string, string | undefined>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(updates)) {
      if (value === undefined) next.delete(key); else next.set(key, value);
    }
    setParams(next);
  };
  const [selected, setSelected] = useState<Workspace>();
  const [drawer, setDrawer] = useState<'detail' | 'account' | 'workspace' | 'binding' | 'manual' | 'target' | 'target-detail' | 'import' | 'batch-preview'>();
  const [activeRead, setActiveRead] = useState<string>();
  const [activeReadWorkspace, setActiveReadWorkspace] = useState<string>();
  const [selectedTargetID, setSelectedTargetID] = useState<string>();
  const [selectedTargetIDs, setSelectedTargetIDs] = useState<string[]>([]);
  const [selectionBatch, setSelectionBatch] = useState<string>();
  const [joinConfirmOpen, setJoinConfirmOpen] = useState(false);
  const [removalConfirmOpen, setRemovalConfirmOpen] = useState(false);
  const [cardMembershipID, setCardMembershipID] = useState<string>();
  const [cardSecretDraft, setCardSecretDraft] = useState<string>();
  const [cardDraftSaved, setCardDraftSaved] = useState(false);
  const [importContent, setImportContent] = useState('');
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
    enabled: Boolean(selectedWorkspaceID),
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
  const targets = useQuery({
    queryKey: ['target-accounts', targetPage, targetPageSize, targetSearch, targetStatus, targetProbeStatus, targetSort],
    enabled: activeStep === '2' || activeStep === '3',
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/target-accounts', {
        params: { query: {
          page: targetPage, page_size: targetPageSize, sort: targetSort as 'created_desc' | 'identifier_asc' | 'probed_desc',
          ...(targetSearch ? { search: targetSearch } : {}),
          ...(targetStatus ? { status: targetStatus as 'active' | 'disabled' } : {}),
          ...(targetProbeStatus ? { probe_status: targetProbeStatus as 'available' | 'credential_invalid' | 'definitely_unavailable' | 'transient_failure' | 'unknown' | 'unprobed' } : {}),
        } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const targetDetail = useQuery<TargetAccountDetail>({
    queryKey: ['target-account-detail', selectedTargetID],
    enabled: Boolean(selectedTargetID),
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/target-accounts/{targetAccountId}', {
        params: { path: { targetAccountId: selectedTargetID ?? '' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const batches = useQuery({
    queryKey: ['batches', detail.data?.binding?.id],
    enabled: activeStep === '3' && Boolean(detail.data?.binding?.id),
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/batches', {
        params: { query: { binding_id: detail.data?.binding?.id ?? '', page: 1, page_size: 100 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const batchDetail = useQuery<BatchDetail>({
    queryKey: ['batch-detail', selectedBatchID, targetPage, targetPageSize],
    enabled: Boolean(selectedBatchID),
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}', {
        params: { path: { batchId: selectedBatchID ?? '' }, query: { target_page: targetPage, target_page_size: targetPageSize } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const batchPreview = useQuery<BatchPreview>({
    queryKey: ['batch-preview', selectedBatchID, targetPage, targetPageSize],
    enabled: drawer === 'batch-preview' && Boolean(selectedBatchID),
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/preview', {
        params: { path: { batchId: selectedBatchID ?? '' }, query: { target_page: targetPage, target_page_size: targetPageSize } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const deliveries = useQuery<DeliveryList>({
    queryKey: ['batch-deliveries', selectedBatchID],
    enabled: activeStep === '5' && Boolean(selectedBatchID),
    refetchInterval: (query) => {
      const pending = query.state.data?.items.some((item) => item.status === 'pending' || item.status === 'generating');
      return pending ? 2000 : false;
    },
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/deliveries', {
        params: { path: { batchId: selectedBatchID ?? '' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const joinPreview = useQuery<JoinPreview>({
    queryKey: ['join-preview', selectedBatchID],
    enabled: activeStep === '4' && Boolean(selectedBatchID),
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/join-preview', {
        params: { path: { batchId: selectedBatchID ?? '' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const joinOperation = useQuery<JoinOperation>({
    queryKey: ['join-operation', selectedBatchID, joinTargetPage, joinTargetPageSize],
    enabled: activeStep === '4' && Boolean(selectedBatchID),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'queued' || status === 'running' ? 2000 : false;
    },
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/join-operation', {
        params: { path: { batchId: selectedBatchID ?? '' }, query: { target_page: joinTargetPage, target_page_size: joinTargetPageSize } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const removalPreview = useQuery<RemovalPreview>({
    queryKey: ['removal-preview', selectedBatchID],
    enabled: activeStep === '6' && Boolean(selectedBatchID),
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/remove-preview', {
        params: { path: { batchId: selectedBatchID ?? '' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const removalOperation = useQuery<RemovalOperation>({
    queryKey: ['removal-operation', selectedBatchID, joinTargetPage, joinTargetPageSize],
    enabled: activeStep === '6' && Boolean(selectedBatchID) && (removalPreview.data?.batch.status === 'removing' || removalPreview.data?.batch.status === 'ended'),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'queued' || status === 'running' ? 2000 : false;
    },
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/remove-operation', {
        params: { path: { batchId: selectedBatchID ?? '' }, query: { target_page: joinTargetPage, target_page_size: joinTargetPageSize } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const refreshJoinEvidence = useMutation({
    mutationFn: async () => {
      if (!selectedBatchID || !joinPreview.data?.batch.workspaceId) throw new Error('请选择一个批次');
      const header = await mutationHeaders();
      const workspaceRead = ownerApi.POST('/api/owner/v1/workspaces/{workspaceId}/refresh', {
        params: { path: { workspaceId: joinPreview.data.batch.workspaceId }, header },
        body: { idempotencyKey: crypto.randomUUID() },
      });
      const reconciliation = joinOperation.data?.status === 'blocked'
        ? ownerApi.POST('/api/owner/v1/batches/{batchId}/join-reconcile', {
          params: { path: { batchId: selectedBatchID }, header },
          body: { idempotencyKey: crypto.randomUUID() },
        })
        : Promise.resolve({ error: undefined });
      const responses = await Promise.all([workspaceRead, reconciliation]);
      for (const response of responses) {
        if (response.error) throw apiFailure(response.error, response.response.status);
      }
      await Promise.all([joinPreview.refetch(), joinOperation.refetch()]);
    },
  });
  const autoRefreshKey = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (params.get('refresh') !== '1' || !selectedBatchID || !joinPreview.data || autoRefreshKey.current === selectedBatchID) return;
    autoRefreshKey.current = selectedBatchID;
    updateParams({ refresh: undefined });
    refreshJoinEvidence.mutate();
  }, [joinPreview.data, params, refreshJoinEvidence, selectedBatchID]);

  const createJoin = useMutation({
    mutationFn: async () => {
      if (!selectedBatchID) throw new Error('请选择一个批次');
      const response = await ownerApi.POST('/api/owner/v1/batches/{batchId}/join', {
        params: { path: { batchId: selectedBatchID }, header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID(), confirm: true },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      setJoinConfirmOpen(false);
      await queryClient.invalidateQueries({ queryKey: ['join-operation', selectedBatchID] });
      await queryClient.invalidateQueries({ queryKey: ['batch-detail', selectedBatchID] });
      message.success('已保存确认并排队加入；平台调用将在 worker 中执行。');
    },
  });
  const refreshRemovalFacts = useMutation({
    mutationFn: async () => {
      if (!selectedBatchID || !removalPreview.data?.batch.workspaceId) throw new Error('请选择一个当前批次');
      const header = await mutationHeaders();
      const refreshResponse = await ownerApi.POST('/api/owner/v1/workspaces/{workspaceId}/refresh', {
        params: { path: { workspaceId: removalPreview.data.batch.workspaceId }, header },
        body: { idempotencyKey: crypto.randomUUID() },
      });
      if (refreshResponse.error) throw apiFailure(refreshResponse.error, refreshResponse.response.status);
      if (removalOperation.data?.status === 'blocked') {
        const reconcileResponse = await ownerApi.POST('/api/owner/v1/batches/{batchId}/remove-reconcile', {
          params: { path: { batchId: selectedBatchID }, header },
          body: { idempotencyKey: crypto.randomUUID() },
        });
        if (reconcileResponse.error) throw apiFailure(reconcileResponse.error, reconcileResponse.response.status);
      }
    },
    onSuccess: async () => {
      await Promise.all([removalPreview.refetch(), removalOperation.refetch()]);
      message.success('已排队读取最新成员事实；未知目标只会先执行只读对账。');
    },
  });
  const createRemoval = useMutation({
    mutationFn: async () => {
      if (!selectedBatchID) throw new Error('请选择一个当前批次');
      const response = await ownerApi.POST('/api/owner/v1/batches/{batchId}/remove', {
        params: { path: { batchId: selectedBatchID }, header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID(), confirm: true },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      setRemovalConfirmOpen(false);
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['removal-operation', selectedBatchID] }),
        queryClient.invalidateQueries({ queryKey: ['removal-preview', selectedBatchID] }),
        queryClient.invalidateQueries({ queryKey: ['batch-detail', selectedBatchID] }),
      ]);
      message.success('已冻结当前批精确目标并排队移除；下一批不会自动加入。');
    },
  });

  const probeDeliveries = useMutation({
    mutationFn: async () => {
      if (!selectedBatchID) throw new Error('请选择一个批次');
      const response = await ownerApi.POST('/api/owner/v1/batches/{batchId}/deliveries/probe', {
        params: { path: { batchId: selectedBatchID }, header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID() },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async (result) => {
      await deliveries.refetch();
      message.success(`已排队 ${result.queued} 个只读 OAuth 验活任务。`);
    },
  });

  const activateCard = useMutation({
    mutationFn: async (values: { membershipId: string; secret: string }) => {
      const response = await ownerApi.POST('/api/owner/v1/memberships/{membershipId}/card', {
        params: { path: { membershipId: values.membershipId }, header: await mutationHeaders() },
        body: { cardSecret: values.secret, idempotencyKey: crypto.randomUUID() },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      setCardMembershipID(undefined);
      setCardSecretDraft(undefined);
      setCardDraftSaved(false);
      await deliveries.refetch();
      message.success('卡密已激活；原值不会再次从服务端显示。');
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

  const createTarget = useMutation({
    mutationFn: async (values: {
      identifier: string;
      displayLabel?: string;
      password: string;
      totpSecret?: string;
      recoverySecret?: string;
      platformSubjectId?: string;
    }) => {
      const response = await ownerApi.POST('/api/owner/v1/target-accounts', {
        params: { header: await mutationHeaders() }, body: values,
      });
      if (response.error) throw apiFailure(response.error, response.response.status);
    },
    onSuccess: async () => {
      setDrawer(undefined);
      await queryClient.invalidateQueries({ queryKey: ['target-accounts'] });
      message.success('目标账号已保存；秘密材料不会回显。');
    },
  });
  const previewImport = useMutation({
    mutationFn: async (content: string) => {
      const response = await ownerApi.POST('/api/owner/v1/target-accounts/import-preview', {
        params: { header: await mutationHeaders() }, body: { content },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });
  const importTargets = useMutation({
    mutationFn: async (content: string) => {
      const response = await ownerApi.POST('/api/owner/v1/target-accounts/import', {
        params: { header: await mutationHeaders() }, body: { content },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async (result) => {
      await queryClient.invalidateQueries({ queryKey: ['target-accounts'] });
      message.success(`导入完成：新增 ${result.created}，已存在 ${result.existing}。`);
      setImportContent('');
      previewImport.reset();
    },
  });
  const updateTarget = useMutation({
    mutationFn: async (values: {
      id: string;
      version: number;
      displayLabel: string;
      status: 'active' | 'disabled';
      password?: string;
      totpSecret?: string;
      recoverySecret?: string;
      platformSubjectId?: string;
    }) => {
      const { id, version, ...body } = values;
      const response = await ownerApi.PATCH('/api/owner/v1/target-accounts/{targetAccountId}', {
        params: { path: { targetAccountId: id }, header: { ...(await mutationHeaders()), 'If-Match': `"${version}"` } }, body,
      });
      if (response.error) throw apiFailure(response.error, response.response.status);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['target-accounts'] });
      await queryClient.invalidateQueries({ queryKey: ['target-account-detail', selectedTargetID] });
      setDrawer('target');
      message.success('目标账号已更新；未提供的秘密材料保持不变。');
    },
  });
  const probeTargets = useMutation({
    mutationFn: async () => {
      const response = await ownerApi.POST('/api/owner/v1/target-account-probes', {
        params: { header: await mutationHeaders() },
        body: {
          idempotencyKey: crypto.randomUUID(),
          ...(selectedTargetIDs.length ? { targetAccountIds: selectedTargetIDs } : {}),
          ...(targetSearch ? { search: targetSearch } : {}),
          ...(targetStatus ? { status: targetStatus as 'active' | 'disabled' } : {}),
          ...(targetProbeStatus && targetProbeStatus !== 'unprobed' ? { probeStatus: targetProbeStatus as 'available' | 'credential_invalid' | 'definitely_unavailable' | 'transient_failure' | 'unknown' } : {}),
        },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: (result) => {
      message.success(`已排队 ${result.total} 个只读可用性探测。`);
    },
  });
  const saveBatch = useMutation({
    mutationFn: async (values: { plannedAt: string; targetAccountIds: string[] }) => {
      if (!detail.data?.binding?.id) throw new Error('当前 Workspace 尚未建立母号关系');
      if (selectionBatch && batchDetail.data) {
        const response = await ownerApi.PUT('/api/owner/v1/batches/{batchId}', {
          params: { path: { batchId: selectionBatch }, header: { ...(await mutationHeaders()), 'If-Match': `"${batchDetail.data.batch.version}"` } },
          body: values,
        });
        if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
        return response.data;
      }
      const response = await ownerApi.POST('/api/owner/v1/batches', {
        params: { header: await mutationHeaders() },
        body: { bindingId: detail.data.binding.id, ...values },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async (result) => {
      updateParams({ batch: result.id, step: '3' });
      setSelectionBatch(result.id);
      await queryClient.invalidateQueries({ queryKey: ['batches'] });
      await queryClient.invalidateQueries({ queryKey: ['batch-detail', result.id] });
      message.success('本批安排已保存；计划时间不会自动产生平台副作用。');
    },
  });
  useEffect(() => {
    if (batchDetail.data && selectedBatchID === batchDetail.data.batch.id) {
      setSelectionBatch(selectedBatchID);
    }
  }, [batchDetail.data, selectedBatchID]);

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

  const targetStatusLabel = (value?: string) => value === 'available' ? '可用' : value === 'credential_invalid' ? '凭据失效' : value === 'definitely_unavailable' ? '确定不可用' : value === 'transient_failure' ? '瞬态失败' : value === 'unknown' ? '无法确认' : '未探测';
  const secondStep = (
    <div className="workflow-step">
      <Alert type="info" showIcon title="本步要完成什么" description="录入目标账号及认证材料，筛选并排除当前不可用目标；只读探测不会加入、移除或刷新成员。" />
      <Space wrap className="section-heading">
        <Button type="primary" onClick={() => setDrawer('target')}>添加目标账号</Button>
        <Button icon={<UploadOutlined />} onClick={() => setDrawer('import')}>导入 CSV</Button>
        <Button icon={<PlayCircleOutlined />} loading={probeTargets.isPending} onClick={() => probeTargets.mutate()}>探测当前筛选</Button>
        <Input.Search placeholder="搜索标识或显示名称" defaultValue={targetSearch} onSearch={(value) => updateParams({ target_search: value || undefined, target_page: '1' })} allowClear />
        <Select placeholder="账号状态" value={targetStatus || undefined} allowClear style={{ width: 130 }} onChange={(value) => updateParams({ target_status: value, target_page: '1' })} options={[{ value: 'active', label: '启用' }, { value: 'disabled', label: '停用' }]} />
        <Select placeholder="探测状态" value={targetProbeStatus || undefined} allowClear style={{ width: 150 }} onChange={(value) => updateParams({ target_probe_status: value, target_page: '1' })} options={['available', 'credential_invalid', 'definitely_unavailable', 'transient_failure', 'unknown', 'unprobed'].map((value) => ({ value, label: targetStatusLabel(value) }))} />
        <Select value={targetSort} style={{ width: 150 }} onChange={(value) => updateParams({ target_sort: value, target_page: '1' })} options={[{ value: 'created_desc', label: '最近录入' }, { value: 'identifier_asc', label: '标识升序' }, { value: 'probed_desc', label: '最近探测' }]} />
      </Space>
      <MutationAlert error={createTarget.error} onRetry={createTarget.variables ? () => createTarget.mutate(createTarget.variables) : undefined} />
      <MutationAlert error={probeTargets.error} onRetry={() => probeTargets.mutate()} />
      {targets.isLoading ? <Spin /> : targets.isError ? <Alert type="error" showIcon title="无法载入目标账号" action={<Button onClick={() => void targets.refetch()}>重试</Button>} /> : (
        <Table<TargetAccount>
          rowKey="id"
          size="small"
          rowSelection={{ preserveSelectedRowKeys: true, selectedRowKeys: selectedTargetIDs, onChange: (keys) => setSelectedTargetIDs(keys as string[]) }}
          dataSource={targets.data?.items ?? []}
          pagination={{ current: targets.data?.page ?? targetPage, pageSize: targets.data?.pageSize ?? targetPageSize, total: targets.data?.total ?? 0, showSizeChanger: true }}
          onChange={(pagination) => updateParams({ target_page: String(pagination.current ?? 1), target_page_size: String(pagination.pageSize ?? 20) })}
          scroll={{ x: 900 }}
          columns={[
            { title: '目标账号', dataIndex: 'displayLabel', key: 'label' },
            { title: '标识', dataIndex: 'identifier', key: 'identifier' },
            { title: '认证材料', key: 'secrets', render: (_, item) => `${item.hasPassword ? '密码' : ''}${item.hasTotp ? ' · TOTP' : ''}${item.hasRecovery ? ' · 恢复码' : ''}` || '缺少' },
            { title: '最近探测', key: 'probe', render: (_, item) => item.latestProbeStatus ? `${targetStatusLabel(item.latestProbeStatus)}${item.latestProbedAt ? ` · ${new Date(item.latestProbedAt).toLocaleString()}` : ''}` : '未探测' },
            { title: '操作', key: 'actions', render: (_, item) => <Space><Button size="small" icon={<EditOutlined />} onClick={() => { setSelectedTargetID(item.id); setDrawer('target-detail'); }}>查看与更新</Button></Space> },
          ]}
        />
      )}
      <Alert type="warning" showIcon title="下一步" description="完成目标账号准备后进入第 3 步；保存批次仍不会授权任何平台成员副作用。" />
    </div>
  );
  const thirdStep = (
    <div className="workflow-step">
      <Alert type="info" showIcon title="本步要完成什么" description="在当前母号—Workspace 关系下持久选择目标、设置计划时间并复核范围。计划时间到达不会自动加入成员。" />
      {!detail.data?.binding ? <Alert type="warning" showIcon title="当前 Workspace 尚未建立管理员关系" description="返回第 1 步建立关系后才能保存批次。" /> : <>
        <Space wrap className="section-heading">
          <Select value={selectedBatchID || undefined} allowClear placeholder="选择已有批次" style={{ width: 300 }} onChange={(value) => { updateParams({ batch: value }); setSelectionBatch(value); }} options={(batches.data?.items ?? []).map((item: Batch) => ({ value: item.id, label: `第 ${item.sequenceNo} 批 · ${new Date(item.plannedAt).toLocaleString()} · ${item.targetCount} 个目标` }))} />
          <Button onClick={() => { updateParams({ batch: undefined }); setSelectionBatch(undefined); setSelectedTargetIDs([]); }}>新建批次</Button>
          <Button icon={<FilterOutlined />} onClick={() => updateParams({ step: '2' })}>筛选目标</Button>
          <Typography.Text>已选择 {selectedTargetIDs.length} 个目标</Typography.Text>
        </Space>
        {batches.isLoading && <Spin />}
        <Table<TargetAccount>
          rowKey="id"
          size="small"
          rowSelection={{ preserveSelectedRowKeys: true, selectedRowKeys: selectedTargetIDs, onChange: (keys) => setSelectedTargetIDs(keys as string[]) }}
          dataSource={targets.data?.items ?? []}
          pagination={{ current: targets.data?.page ?? targetPage, pageSize: targets.data?.pageSize ?? targetPageSize, total: targets.data?.total ?? 0, showSizeChanger: true }}
          onChange={(pagination) => updateParams({ target_page: String(pagination.current ?? 1), target_page_size: String(pagination.pageSize ?? 20) })}
          scroll={{ x: 820 }}
          columns={[{ title: '目标账号', dataIndex: 'displayLabel', key: 'label' }, { title: '标识', dataIndex: 'identifier', key: 'identifier' }, { title: '探测状态', key: 'probe', render: (_, item) => targetStatusLabel(item.latestProbeStatus) }, { title: '状态', dataIndex: 'status', key: 'status' }]}
        />
        <Form layout="inline" onFinish={(values: { plannedAt: PlannedAtValue }) => saveBatch.mutate({ plannedAt: values.plannedAt.toISOString(), targetAccountIds: selectedTargetIDs })} initialValues={{ plannedAt: selectedBatchID && batchDetail.data ? undefined : undefined }}>
          <Form.Item name="plannedAt" label="计划处理时间" rules={[{ required: true, message: '请选择计划时间' }]}><DatePicker showTime /></Form.Item>
          <Button type="primary" icon={<SaveOutlined />} htmlType="submit" loading={saveBatch.isPending} disabled={!detail.data.binding || selectedTargetIDs.length === 0}>保存本批安排</Button>
          {selectedBatchID && <Button onClick={() => setDrawer('batch-preview')}>查看范围预览</Button>}
        </Form>
        <MutationAlert error={saveBatch.error} onRetry={() => undefined} />
      </>}
    </div>
  );

  const fourthStep = (
    <div className="workflow-step">
      <Alert type="info" showIcon title="本步要完成什么" description="确认整个冻结批次的加入。当前 Workspace 证据和批次范围会在提交时再次校验；执行时逐目标实时探测，未知结果只进入需要处理，不提供盲目重试。" />
      {!selectedBatchID ? <Alert type="warning" showIcon title="还没有选择批次" description="返回第 3 步保存或选择一个计划批次。" /> : <>
        <Space wrap className="section-heading">
          <Button icon={<ReloadOutlined />} onClick={() => refreshJoinEvidence.mutate()} loading={refreshJoinEvidence.isPending || joinPreview.isFetching}>刷新当前证据</Button>
          <MutationAlert error={refreshJoinEvidence.error} onRetry={() => refreshJoinEvidence.mutate()} />
        </Space>
        {joinPreview.isLoading && <Spin />}
        {joinPreview.isError && <Alert type="error" showIcon title="无法载入加入证据" description="请刷新当前证据；刷新不会创建平台操作。" action={<Button onClick={() => void joinPreview.refetch()}>重新读取</Button>} />}
        {joinPreview.data && <>
          <Descriptions bordered size="small" column={1} items={[
            { key: 'workspace', label: '冻结团队空间', children: `${joinPreview.data.batch.workspaceName} · ${joinPreview.data.batch.workspaceId}` },
            { key: 'batch', label: '冻结批次', children: `第 ${joinPreview.data.batch.sequenceNo} 批 · ${joinPreview.data.batch.targetCount} 个目标` },
            { key: 'evidence', label: 'Workspace 证据', children: `${joinPreview.data.operationalState} · ${joinPreview.data.evidenceSource ?? '证据不足'} · ${joinPreview.data.evidenceObservedAt ? new Date(joinPreview.data.evidenceObservedAt).toLocaleString() : '无'}` },
            { key: 'snapshot', label: '成员快照', children: `${joinPreview.data.snapshotCompleteness} · ${joinPreview.data.snapshotSource ?? '证据不足'} · ${joinPreview.data.snapshotObservedAt ? new Date(joinPreview.data.snapshotObservedAt).toLocaleString() : '无'}` },
            { key: 'capacity', label: '可解释容量', children: joinPreview.data.availableSeats ?? '证据不足' },
          ]} />
          {joinPreview.data.blockers.length > 0 && <Alert type="warning" showIcon icon={<WarningOutlined />} title="当前不能确认加入" description={<ul>{joinPreview.data.blockers.map((item) => <li key={item.code}>{item.message}</li>)}</ul>} />}
          {joinPreview.data.canProceed && <Button type="primary" onClick={() => setJoinConfirmOpen(true)} disabled={createJoin.isPending || joinOperation.data?.status === 'queued' || joinOperation.data?.status === 'running'}>确认加入整个批次</Button>}
        </>}
        {joinOperation.data && <>
          <Alert
            type={joinOperation.data.status === 'succeeded' ? 'success' : joinOperation.data.status === 'blocked' ? 'warning' : joinOperation.data.status === 'failed' ? 'error' : 'info'}
            showIcon
            title={`加入操作：${joinOperation.data.status}`}
            description={joinOperation.data.status === 'blocked' ? '平台结果未知或网络路径被阻断。请查看逐目标结果并完成事实对账，不要盲目重新提交。' : `进度：${joinOperation.data.succeededCount} 成功 / ${joinOperation.data.failedCount} 失败 / ${joinOperation.data.blockedCount} 阻塞 / ${joinOperation.data.pendingCount} 待处理`}
          />
          <Table<JoinOperationTarget>
            rowKey="id"
            size="small"
            dataSource={joinOperation.data.targets}
            pagination={{ current: joinOperation.data.targetPage, pageSize: joinOperation.data.targetPageSize, total: joinOperation.data.targetTotal, showSizeChanger: true }}
            onChange={(pagination) => updateParams({ join_target_page: String(pagination.current ?? 1), join_target_page_size: String(pagination.pageSize ?? 20) })}
            scroll={{ x: 920 }}
            columns={[
              { title: '目标账号', dataIndex: 'targetAccountId', key: 'account' },
              { title: '当前结果', key: 'result', render: (_, item) => `${item.status} · ${item.diagnosticCode ?? item.outcomeCode ?? item.preflightStatus}` },
              { title: '实时门禁', dataIndex: 'preflightStatus', key: 'preflight' },
              { title: '主操作', key: 'action', render: (_, item) => item.status === 'blocked' || item.status === 'unknown' ? <Button size="small" loading={refreshJoinEvidence.isPending} onClick={() => refreshJoinEvidence.mutate()}>核对成员事实</Button> : <Typography.Text type="secondary">无需处理</Typography.Text> },
            ]}
          />
        </>}
      </>}
      <Modal open={joinConfirmOpen} title="确认加入团队" okText="明确确认并排队" cancelText="取消" confirmLoading={createJoin.isPending} onCancel={() => setJoinConfirmOpen(false)} onOk={() => createJoin.mutate()}>
        {joinPreview.data && <Descriptions size="small" column={1} items={[
          { key: 'workspace', label: '团队空间', children: joinPreview.data.batch.workspaceName },
          { key: 'batch', label: '批次', children: `第 ${joinPreview.data.batch.sequenceNo} 批` },
          { key: 'scope', label: '范围', children: `冻结批次全部 ${joinPreview.data.batch.targetCount} 个目标` },
        ]} />}
        <Alert className="modal-alert" type="warning" showIcon title="平台成功响应不会直接建立成员关系" description="系统会先执行实时目标探测，再发送已授权请求，并重新读取成员事实。只有确认目标已成为该 Workspace 成员后，才记录实际加入时间。" />
      </Modal>
    </div>
  );

  const fifthStep = (
    <div className="workflow-step">
      <Alert type="info" showIcon title="本步要完成什么" description="等待每个已确认成员的 OAuth 交付完成；只对明确可交付的关系生成卡密。卡密原值由浏览器生成，保存前不会提交服务端。" />
      {!selectedBatchID ? <Alert type="warning" showIcon title="还没有选择批次" description="返回第 3 步选择已确认加入的批次。" /> : deliveries.isLoading ? <Spin /> : deliveries.isError ? <Alert type="error" showIcon title="无法载入交付状态" action={<Button onClick={() => void deliveries.refetch()}>重试</Button>} /> : (
        <>
          <Space className="section-heading" wrap>
            <Button icon={<ReloadOutlined />} loading={probeDeliveries.isPending} onClick={() => probeDeliveries.mutate()}>批量验活</Button>
            <MutationAlert error={probeDeliveries.error} onRetry={() => probeDeliveries.mutate()} />
          </Space>
          <Table<Delivery>
          rowKey="membershipId"
          size="small"
          dataSource={deliveries.data?.items ?? []}
          scroll={{ x: 820 }}
          pagination={false}
          columns={[
            { title: '目标账号', dataIndex: 'targetAccountId', key: 'target' },
            { title: 'OAuth 交付', dataIndex: 'status', key: 'status', render: (value: string, item) => `${value}${item.livenessStatus ? ` · ${item.livenessStatus}` : ''}` },
            { title: '探测时间', dataIndex: 'probedAt', key: 'probedAt', render: (value?: string) => value ? new Date(value).toLocaleString() : '尚未完成' },
            { title: '卡密', key: 'card', render: (_, item) => item.cardActivated ? `已激活 · ${item.cardDisplaySuffix ?? ''}` : item.status === 'ready' ? <Button size="small" icon={<KeyOutlined />} onClick={() => { setCardMembershipID(item.membershipId); setCardSecretDraft(generateCardSecret()); setCardDraftSaved(false); }}>生成卡密</Button> : <Typography.Text type="secondary">等待交付就绪</Typography.Text> },
          ]}
        />
        </>
      )}
      <Modal
        open={Boolean(cardMembershipID && cardSecretDraft)}
        title="保存卡密原值"
        okText="已保存，激活卡密"
        cancelText="取消"
        okButtonProps={{ disabled: !cardDraftSaved }}
        confirmLoading={activateCard.isPending}
        onCancel={() => { setCardMembershipID(undefined); setCardSecretDraft(undefined); setCardDraftSaved(false); }}
        onOk={() => { if (cardMembershipID && cardSecretDraft && cardDraftSaved) activateCard.mutate({ membershipId: cardMembershipID, secret: cardSecretDraft }); }}
      >
        <Alert type="warning" showIcon title="卡密原值只显示这一次" description="先复制或下载并确认已保存，再激活。服务端不会保存或回显原值。" />
        <Input.Password readOnly value={cardSecretDraft} className="modal-field" />
        <Space>
          <Button icon={<CopyOutlined />} onClick={async () => { if (cardSecretDraft) { await navigator.clipboard.writeText(cardSecretDraft); setCardDraftSaved(true); message.success('卡密已复制'); } }}>复制并标记已保存</Button>
          <Button icon={<DownloadOutlined />} onClick={() => { if (!cardSecretDraft) return; const url = URL.createObjectURL(new Blob([`${cardSecretDraft}\n`], { type: 'text/plain' })); const link = document.createElement('a'); link.href = url; link.download = 'teamseatwatch-card.txt'; link.click(); URL.revokeObjectURL(url); setCardDraftSaved(true); }}>下载并标记已保存</Button>
        </Space>
        <MutationAlert error={activateCard.error} />
      </Modal>
    </div>
  );

  const sixthStep = (
    <div className="workflow-step">
      <Alert type="info" showIcon title="本步要完成什么" description="计划时间到达后核对当前批成员关系、100% 完整成员快照和差异，再明确确认只移除这批关系。Owner、未知成员和其他批次成员始终受保护。" />
      {!selectedBatchID ? <Alert type="warning" showIcon title="还没有选择当前批次" description="返回第 3 步选择服务中的批次。" /> : <>
        <Space wrap className="section-heading">
          <Button icon={<ReloadOutlined />} loading={refreshRemovalFacts.isPending} onClick={() => refreshRemovalFacts.mutate()}>读取最新事实</Button>
          <MutationAlert error={refreshRemovalFacts.error} onRetry={() => refreshRemovalFacts.mutate()} />
        </Space>
        {removalPreview.isLoading && <Spin />}
        {removalPreview.isError && <Alert type="error" showIcon title="无法载入移除预览" action={<Button onClick={() => void removalPreview.refetch()}>重试</Button>} />}
        {removalPreview.data && <>
          <Descriptions bordered size="small" column={1} items={[
            { key: 'workspace', label: '冻结团队空间', children: removalPreview.data.batch.workspaceName },
            { key: 'batch', label: '当前批次', children: `第 ${removalPreview.data.batch.sequenceNo} 批` },
            { key: 'scope', label: '精确关系范围', children: `${removalPreview.data.targets.length} 个已确认批次关系` },
            { key: 'snapshot', label: '最新成员快照', children: `${removalPreview.data.snapshotCompleteness} · ${removalPreview.data.declaredMemberCount ?? '未知'} 个成员 · ${removalPreview.data.snapshotObservedAt ? new Date(removalPreview.data.snapshotObservedAt).toLocaleString() : '尚未读取'}` },
          ]} />
          {removalPreview.data.differences.length > 0 && <Alert type="warning" showIcon title="发现受保护的成员差异" description={<ul>{removalPreview.data.differences.map((item) => <li key={`${item.reason}:${item.identifier}`}>{item.identifier} · {item.role || '未提供角色'} · {item.reason}</li>)}</ul>} />}
          {removalPreview.data.blockers.length > 0 && <Alert type="warning" showIcon title="当前不能确认移除" description={<ul>{removalPreview.data.blockers.map((item) => <li key={item.code}>{item.message}</li>)}</ul>} />}
          <Table
            rowKey="membershipId"
            size="small"
            pagination={false}
            dataSource={removalPreview.data.targets}
            scroll={{ x: 720 }}
            columns={[
              { title: '目标成员', dataIndex: 'displayLabel', key: 'label' },
              { title: '核对标识', dataIndex: 'identifier', key: 'identifier' },
              { title: '最新事实', dataIndex: 'state', key: 'state' },
              { title: '范围', key: 'scope', render: () => '仅当前批关系' },
            ]}
          />
          {removalPreview.data.canProceed && <Button danger type="primary" onClick={() => setRemovalConfirmOpen(true)} disabled={createRemoval.isPending || removalOperation.data?.status === 'queued' || removalOperation.data?.status === 'running'}>确认精确移除当前批</Button>}
        </>}
        {removalOperation.data && <>
          <Alert
            type={removalOperation.data.status === 'succeeded' ? 'success' : removalOperation.data.status === 'blocked' ? 'warning' : 'info'}
            showIcon
            title={`移除操作：${removalOperation.data.status}`}
            description={removalOperation.data.status === 'succeeded' ? '当前批每个精确目标均已确认不存在；客户服务已结束。下一批仍需独立确认加入。' : `${removalOperation.data.succeededCount} 已确认移除 / ${removalOperation.data.blockedCount} 阻塞 / ${removalOperation.data.pendingCount} 待处理`}
          />
          <Table<RemovalOperationTarget>
            rowKey="id"
            size="small"
            dataSource={removalOperation.data.targets}
            pagination={{ current: removalOperation.data.targetPage, pageSize: removalOperation.data.targetPageSize, total: removalOperation.data.targetTotal, showSizeChanger: true }}
            onChange={(pagination) => updateParams({ join_target_page: String(pagination.current ?? 1), join_target_page_size: String(pagination.pageSize ?? 20) })}
            scroll={{ x: 820 }}
            columns={[
              { title: '目标成员', dataIndex: 'displayLabel', key: 'label' },
              { title: '当前结果', key: 'result', render: (_, item) => `${item.status} · ${item.diagnosticCode ?? item.outcomeCode ?? '等待处理'}` },
              { title: 'DELETE 尝试', dataIndex: 'attemptCount', key: 'attempts' },
              { title: '处理', key: 'action', render: (_, item) => item.status === 'blocked' || item.status === 'unknown' ? <Button size="small" loading={refreshRemovalFacts.isPending} onClick={() => refreshRemovalFacts.mutate()}>读取最新事实</Button> : <Typography.Text type="secondary">无需处理</Typography.Text> },
            ]}
          />
        </>}
      </>}
      <Modal open={removalConfirmOpen} title="确认精确移除当前批？" okText="明确确认并排队" cancelText="取消" okButtonProps={{ danger: true }} confirmLoading={createRemoval.isPending} onCancel={() => setRemovalConfirmOpen(false)} onOk={() => createRemoval.mutate()}>
        {removalPreview.data && <Space orientation="vertical" size="middle" className="full-width">
          <Descriptions bordered size="small" column={1} items={[
            { key: 'workspace', label: '团队空间', children: removalPreview.data.batch.workspaceName },
            { key: 'batch', label: '批次', children: `第 ${removalPreview.data.batch.sequenceNo} 批` },
            { key: 'targets', label: '冻结目标', children: `${removalPreview.data.targets.length} 个当前批成员关系` },
          ]} />
          <Alert type="warning" showIcon title="不会清退 Workspace 的普通成员全集" description="worker 会在每次 DELETE 前重新读取 100% 完整快照、确认 Owner，并使用当前批关系的核对标识找到实时 member.id。未知结果只先对账；任一目标未确认消失时不会结束批次或推进下一批。" />
          <MutationAlert error={createRemoval.error} />
        </Space>}
      </Modal>
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
          children: index === 0 ? firstStep : index === 1 ? secondStep : index === 2 ? thirdStep : index === 3 ? fourthStep : index === 4 ? fifthStep : sixthStep,
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
      <Drawer title="添加目标账号" open={drawer === 'target'} onClose={() => setDrawer(undefined)} size={480}>
        <MutationAlert error={createTarget.error} onRetry={createTarget.variables ? () => createTarget.mutate(createTarget.variables) : undefined} />
        <Form layout="vertical" onFinish={(values) => createTarget.mutate(values)}>
          <Form.Item name="identifier" label="登录标识" rules={[{ required: true }]}><Input autoComplete="off" /></Form.Item>
          <Form.Item name="displayLabel" label="显示名称"><Input /></Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true }]}><Input.Password autoComplete="new-password" /></Form.Item>
          <Form.Item name="totpSecret" label="TOTP 秘密"><Input.Password autoComplete="new-password" /></Form.Item>
          <Form.Item name="recoverySecret" label="恢复秘密"><Input.Password autoComplete="new-password" /></Form.Item>
          <Form.Item name="platformSubjectId" label="平台账号标识"><Input /></Form.Item>
          <Button type="primary" htmlType="submit" loading={createTarget.isPending}>保存目标账号</Button>
        </Form>
      </Drawer>
      <Drawer title="导入目标账号" open={drawer === 'import'} onClose={() => setDrawer(undefined)} size={640}>
        <Alert type="info" showIcon title="CSV 列顺序固定" description="identifier,display_label,password,totp_secret,recovery_secret,platform_subject_id。秘密只用于控制服务保存，不会出现在预览、响应或审计中。" />
        <Upload accept=".csv,text/csv" maxCount={1} showUploadList={false} beforeUpload={async (file) => { setImportContent(await file.text()); return false; }}>
          <Button icon={<UploadOutlined />}>选择 CSV</Button>
        </Upload>
        <Typography.Paragraph>{importContent ? `已读取 ${importContent.split(/\r?\n/).length - 1} 行` : '尚未选择文件'}</Typography.Paragraph>
        <Space>
          <Button disabled={!importContent} loading={previewImport.isPending} onClick={() => previewImport.mutate(importContent)}>预览</Button>
          <Button type="primary" disabled={!importContent || !previewImport.data} loading={importTargets.isPending} onClick={() => importTargets.mutate(importContent)}>确认导入</Button>
        </Space>
        {previewImport.data && <Table size="small" rowKey="line" pagination={{ pageSize: 10 }} dataSource={previewImport.data.items} columns={[{ title: '行', dataIndex: 'line' }, { title: '标识', dataIndex: 'identifier' }, { title: '显示名称', dataIndex: 'displayLabel' }, { title: '状态', render: (_, item) => item.existing ? '已存在' : '新增' }]} />}
      </Drawer>
      <Drawer title="目标账号详情与更新" open={drawer === 'target-detail'} onClose={() => setDrawer(undefined)} size={520}>
        {targetDetail.isLoading && <Spin />}
        {targetDetail.data && <>
          <Descriptions bordered size="small" column={1} items={[{ key: 'identifier', label: '标识', children: targetDetail.data.targetAccount.identifier }, { key: 'label', label: '显示名称', children: targetDetail.data.targetAccount.displayLabel }, { key: 'probe', label: '最近探测', children: targetStatusLabel(targetDetail.data.targetAccount.latestProbeStatus) }, { key: 'plans', label: 'Workspace 关系', children: targetDetail.data.workspacePlans.length ? targetDetail.data.workspacePlans.map((plan) => `${plan.workspaceName} · 第 ${plan.sequenceNo} 批`).join('；') : '尚无批次关系' }]} />
          <Form layout="vertical" initialValues={{ displayLabel: targetDetail.data.targetAccount.displayLabel, status: targetDetail.data.targetAccount.status }} onFinish={(values: { displayLabel: string; status: 'active' | 'disabled'; password?: string; totpSecret?: string; recoverySecret?: string; platformSubjectId?: string }) => updateTarget.mutate({ id: targetDetail.data!.targetAccount.id, version: targetDetail.data!.targetAccount.version, displayLabel: values.displayLabel, status: values.status, ...(values.password ? { password: values.password } : {}), ...(values.totpSecret ? { totpSecret: values.totpSecret } : {}), ...(values.recoverySecret ? { recoverySecret: values.recoverySecret } : {}), ...(values.platformSubjectId ? { platformSubjectId: values.platformSubjectId } : {}) })}>
            <Form.Item name="displayLabel" label="显示名称" rules={[{ required: true }]}><Input /></Form.Item>
            <Form.Item name="status" label="状态" rules={[{ required: true }]}><Select options={[{ value: 'active', label: '启用' }, { value: 'disabled', label: '停用' }]} /></Form.Item>
            <Form.Item name="password" label="替换密码"><Input.Password autoComplete="new-password" /></Form.Item>
            <Form.Item name="totpSecret" label="替换 TOTP 秘密"><Input.Password autoComplete="new-password" /></Form.Item>
            <Form.Item name="recoverySecret" label="替换恢复秘密"><Input.Password autoComplete="new-password" /></Form.Item>
            <Form.Item name="platformSubjectId" label="替换平台账号标识"><Input /></Form.Item>
            <Button type="primary" htmlType="submit" loading={updateTarget.isPending}>保存更新</Button>
          </Form>
        </>}
      </Drawer>
      <Drawer title="加入范围预览" open={drawer === 'batch-preview'} onClose={() => setDrawer(undefined)} size={640}>
        {batchPreview.isLoading && <Spin />}
        {batchPreview.data && <Space orientation="vertical" size="middle" className="full-width">
          <Descriptions bordered size="small" column={1} items={[{ key: 'workspace', label: 'Workspace', children: batchPreview.data.batch.workspaceName }, { key: 'batch', label: '批次', children: batchPreview.data.batch.sequenceNo }, { key: 'planned', label: '计划时间', children: new Date(batchPreview.data.batch.plannedAt).toLocaleString() }, { key: 'capacity', label: '容量', children: batchPreview.data.availableSeats ?? '证据不足' }, { key: 'evidence', label: '证据', children: batchPreview.data.evidenceSource ?? '证据不足' }]} />
          {batchPreview.data.blockers.length ? <Alert type="warning" showIcon title="当前不能确认加入" description={<ul>{batchPreview.data.blockers.map((item) => <li key={item.code}>{item.message}</li>)}</ul>} /> : <Alert type="success" showIcon title="当前范围可继续复核" />}
          <Table<TargetAccount> size="small" rowKey="id" dataSource={batchPreview.data.targets} pagination={false} columns={[{ title: '目标账号', dataIndex: 'displayLabel' }, { title: '标识', dataIndex: 'identifier' }, { title: '探测', render: (_, item) => targetStatusLabel(item.latestProbeStatus) }]} />
        </Space>}
      </Drawer>
    </OwnerShell>
  );
}
