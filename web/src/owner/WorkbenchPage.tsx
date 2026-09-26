import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Button, Collapse, Drawer, Input, Modal, Select, Spin, Table } from 'antd';
import { useEffect, useMemo, useState } from 'react';
import type { CSSProperties } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { mutationHeaders, ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure } from './problems';
import { joinOutcomeLabel, probePill, BatchLane, SeatGrid, TimeBar, hoursTone, timeScale } from './ui';
import {
  activeBatch,
  availableSeats,
  deriveFlowCards,
  deriveStageAction,
  deriveZhupi,
  hoursUntil,
  railFacts,
  sortWorkspaces,
  type ActionKind,
} from './workbenchFacts';

// 工作台三栏（规格书 §3）：左空间列表 / 中五段流程卡＋朱批＋动作条 / 右运行面板。
// 页面只渲染 workbenchFacts 的推导结果，不自己判断状态；
// 高风险动作（加入/移除）必须二次确认，弹窗写清影响范围和「什么不受影响」。

const RAIL_PAGE_SIZE = 50;

function localDateTime(offsetHours: number): string {
  const d = new Date(Date.now() + offsetHours * 3_600_000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '操作失败';
}

export default function WorkbenchPage() {
  const { message, modal } = App.useApp();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  const selectedId = params.get('workspace') ?? undefined;
  const [pickerOpen, setPickerOpen] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);
  const [plannedAt, setPlannedAt] = useState(() => localDateTime(72));
  const [bindingOpen, setBindingOpen] = useState(false);
  const [motherPick, setMotherPick] = useState<string | undefined>(undefined);
  const [registerOpen, setRegisterOpen] = useState(false);
  const [registerName, setRegisterName] = useState('');
  const [registerPlatformId, setRegisterPlatformId] = useState('');
  const [activeRead, setActiveRead] = useState<string | undefined>(undefined);

  function select(id: string) {
    setParams({ workspace: id }, { replace: true });
    setActiveRead(undefined);
  }

  // ── 查询 ────────────────────────────────────────────────────────────────

  const workspaces = useQuery({
    queryKey: ['workspaces', 'rail'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/workspaces', {
        params: { query: { page: 1, page_size: RAIL_PAGE_SIZE, sort: 'updated_desc' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const attentionWorkspaces = useQuery({
    queryKey: ['workspaces', 'needs-attention'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/workspaces/needs-attention', {
        params: { query: { page: 1, page_size: RAIL_PAGE_SIZE } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const attentionJoins = useQuery({
    queryKey: ['join-operations', 'needs-attention'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/join-operations/needs-attention', {
        params: { query: { page: 1, page_size: 20 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const attentionRemovals = useQuery({
    queryKey: ['removal-operations', 'needs-attention'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/removal-operations/needs-attention', {
        params: { query: { page: 1, page_size: 20 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const motherAccounts = useQuery({
    queryKey: ['mother-accounts'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/mother-accounts', {
        params: { query: { page: 1, page_size: 100, sort: 'name_asc' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data.items;
    },
  });

  const detail = useQuery({
    queryKey: ['workspace-detail', selectedId, 'workbench'],
    enabled: Boolean(selectedId),
    queryFn: async () => {
      if (!selectedId) throw new Error('请先选择一个空间');
      const response = await ownerApi.GET('/api/owner/v1/workspaces/{workspaceId}', {
        params: {
          path: { workspaceId: selectedId },
          query: { observation_page: 1, observation_page_size: 5, member_page: 1, member_page_size: 10 },
        },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const bindingId = detail.data?.binding?.id;

  const batches = useQuery({
    queryKey: ['batches', bindingId],
    enabled: Boolean(bindingId),
    queryFn: async () => {
      if (!bindingId) throw new Error('还没有关联母号');
      const response = await ownerApi.GET('/api/owner/v1/batches', {
        params: { query: { binding_id: bindingId, page: 1, page_size: 100 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const batch = activeBatch(batches.data?.items);

  const joinPreview = useQuery({
    queryKey: ['join-preview', batch?.id],
    enabled: Boolean(batch) && (batch?.status === 'planned' || batch?.status === 'draft'),
    queryFn: async () => {
      if (!batch) throw new Error('还没有批次');
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/join-preview', {
        params: { path: { batchId: batch.id } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const joinOperation = useQuery({
    queryKey: ['join-operation', batch?.id],
    enabled: Boolean(batch),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'queued' || status === 'running' ? 2000 : false;
    },
    queryFn: async () => {
      if (!batch) throw new Error('还没有批次');
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/join-operation', {
        params: { path: { batchId: batch.id }, query: { target_page: 1, target_page_size: 20 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const removalOperation = useQuery({
    queryKey: ['removal-operation', batch?.id],
    enabled: batch?.status === 'removing',
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === 'queued' || status === 'running' ? 2000 : false;
    },
    queryFn: async () => {
      if (!batch) throw new Error('还没有批次');
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/remove-operation', {
        params: { path: { batchId: batch.id }, query: { target_page: 1, target_page_size: 20 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const batchDetail = useQuery({
    queryKey: ['batch-detail', batch?.id, 'members'],
    enabled: Boolean(batch),
    queryFn: async () => {
      if (!batch) throw new Error('还没有批次');
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}', {
        params: { path: { batchId: batch.id }, query: { target_page: 1, target_page_size: 50 } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const deliveries = useQuery({
    queryKey: ['batch-deliveries', batch?.id],
    enabled: batch?.status === 'serving' || batch?.status === 'removing',
    queryFn: async () => {
      if (!batch) throw new Error('还没有批次');
      const response = await ownerApi.GET('/api/owner/v1/batches/{batchId}/deliveries', {
        params: { path: { batchId: batch.id } },
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
      if (!activeRead) throw new Error('没有进行中的读取');
      const response = await ownerApi.GET('/api/owner/v1/workspace-reads/{readId}', {
        params: { path: { readId: activeRead } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const pickerTargets = useQuery({
    queryKey: ['target-accounts', 'picker'],
    enabled: pickerOpen,
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/target-accounts', {
        params: { query: { page: 1, page_size: 100, sort: 'identifier_asc', status: 'active' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  useEffect(() => {
    setPicked([]);
  }, [pickerOpen]);

  // 重读任务结束后回写事实
  const readFinished = readStatus.data?.status;
  useEffect(() => {
    if (!activeRead || !readFinished) return;
    if (readFinished === 'succeeded' || readFinished === 'failed' || readFinished === 'interrupted') {
      setActiveRead(undefined);
      void queryClient.invalidateQueries({ queryKey: ['workspace-detail'] });
      void queryClient.invalidateQueries({ queryKey: ['join-operation'] });
      void queryClient.invalidateQueries({ queryKey: ['batches'] });
      void queryClient.invalidateQueries({ queryKey: ['workspaces'] });
      if (readFinished === 'succeeded') message.success('成员名单已更新。');
      else message.error('读取没有完成，稍后再试一次。');
    }
  }, [activeRead, readFinished, message, queryClient]);

  // ── 推导 ────────────────────────────────────────────────────────────────

  const attentionIds = useMemo(() => {
    const ids = new Set<string>();
    for (const w of attentionWorkspaces.data?.items ?? []) ids.add(w.id);
    for (const op of attentionJoins.data?.items ?? []) ids.add(op.workspaceId);
    for (const op of attentionRemovals.data?.items ?? []) ids.add(op.workspaceId);
    return ids;
  }, [attentionWorkspaces.data, attentionJoins.data, attentionRemovals.data]);

  const railItems = useMemo(
    () => sortWorkspaces(workspaces.data?.items ?? [], attentionIds),
    [workspaces.data, attentionIds],
  );

  useEffect(() => {
    if (!selectedId && railItems.length > 0 && railItems[0]) select(railItems[0].id);
  }, [selectedId, railItems]);

  const zhupi = deriveZhupi({
    workspace: detail.data?.workspace,
    bindingExists: Boolean(bindingId),
    batch,
    joinOp: joinOperation.data,
  });
  const cards = deriveFlowCards({
    workspace: detail.data?.workspace,
    bindingExists: Boolean(bindingId),
    batch,
    joinOp: joinOperation.data,
    removalOp: removalOperation.data,
    deliveries: deliveries.data?.items,
  });
  const action = deriveStageAction({
    bindingExists: Boolean(bindingId),
    batch,
    joinOp: joinOperation.data,
    removalOp: removalOperation.data,
    zhupi,
  });
  const motherName =
    batch?.motherAccountName ??
    motherAccounts.data?.find((a) => a.id === detail.data?.binding?.motherAccountId)?.displayName;
  const seats = availableSeats(detail.data?.workspace);

  const joinActive =
    joinOperation.data?.status === 'queued' || joinOperation.data?.status === 'running';
  const removalActive =
    removalOperation.data?.status === 'queued' || removalOperation.data?.status === 'running';
  const readActive =
    readStatus.data !== undefined &&
    (readStatus.data.status === 'queued' ||
      readStatus.data.status === 'running' ||
      readStatus.data.status === 'retry_wait');

  // ── 变更 ────────────────────────────────────────────────────────────────

  async function invalidateFacts() {
    await queryClient.invalidateQueries({ queryKey: ['workspace-detail'] });
    await queryClient.invalidateQueries({ queryKey: ['batches'] });
    await queryClient.invalidateQueries({ queryKey: ['join-operation'] });
    await queryClient.invalidateQueries({ queryKey: ['removal-operation'] });
    await queryClient.invalidateQueries({ queryKey: ['batch-deliveries'] });
    await queryClient.invalidateQueries({ queryKey: ['workspaces'] });
  }

  const refreshEvidence = useMutation({
    mutationFn: async () => {
      if (!selectedId) throw new Error('请先选择一个空间');
      const header = await mutationHeaders();
      const refresh = await ownerApi.POST('/api/owner/v1/workspaces/{workspaceId}/refresh', {
        params: { path: { workspaceId: selectedId }, header },
        body: { idempotencyKey: crypto.randomUUID() },
      });
      if (refresh.error || !refresh.data) throw apiFailure(refresh.error, refresh.response.status);
      // 加入结果未知时同时对账：核对 = 重读名单 + 对账，两步一起做（票据 09）
      if (joinOperation.data?.status === 'blocked' && batch) {
        const reconcile = await ownerApi.POST('/api/owner/v1/batches/{batchId}/join-reconcile', {
          params: { path: { batchId: batch.id }, header },
          body: { idempotencyKey: crypto.randomUUID() },
        });
        if (reconcile.error) throw apiFailure(reconcile.error, reconcile.response.status);
      }
      return refresh.data;
    },
    onSuccess: (data) => {
      setActiveRead(data.id);
      message.success('已开始重新读取成员名单。');
    },
    onError: (error) => message.error(errorMessage(error)),
  });

  const createJoin = useMutation({
    mutationFn: async () => {
      if (!batch) throw new Error('还没有可加入的批次');
      const response = await ownerApi.POST('/api/owner/v1/batches/{batchId}/join', {
        params: { path: { batchId: batch.id }, header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID(), confirm: true },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['join-operation'] });
      message.success('已保存确认并排队加入；平台调用将在后台执行。');
    },
    onError: (error) => message.error(errorMessage(error)),
  });

  const createRemove = useMutation({
    mutationFn: async () => {
      if (!batch) throw new Error('还没有可移除的批次');
      const response = await ownerApi.POST('/api/owner/v1/batches/{batchId}/remove', {
        params: { path: { batchId: batch.id }, header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID(), confirm: true },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['removal-operation'] });
      message.success('已保存确认并排队移除；平台调用将在后台执行。');
    },
    onError: (error) => message.error(errorMessage(error)),
  });

  const saveBatch = useMutation({
    mutationFn: async () => {
      if (!bindingId || picked.length === 0) throw new Error('请先选择本批成员');
      const planned = new Date(plannedAt);
      if (Number.isNaN(planned.getTime())) throw new Error('计划处理时间不完整');
      const response = await ownerApi.POST('/api/owner/v1/batches', {
        params: { header: await mutationHeaders() },
        body: { bindingId, plannedAt: planned.toISOString(), targetAccountIds: picked },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      setPickerOpen(false);
      setPicked([]);
      setPlannedAt(localDateTime(72));
      await invalidateFacts();
      message.success('批次已安排。下一步是确认加入。');
    },
    onError: (error) => message.error(errorMessage(error)),
  });

  const createBinding = useMutation({
    mutationFn: async () => {
      if (!selectedId || !motherPick) throw new Error('请选择一个母号');
      const response = await ownerApi.POST('/api/owner/v1/bindings', {
        params: { header: await mutationHeaders() },
        body: { motherAccountId: motherPick, workspaceId: selectedId },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      setBindingOpen(false);
      setMotherPick(undefined);
      await invalidateFacts();
      message.success('母号已关联，正在核对席位和成员。');
    },
    onError: (error) => message.error(errorMessage(error)),
  });

  const registerWorkspace = useMutation({
    mutationFn: async () => {
      if (!registerName.trim() || !registerPlatformId.trim()) throw new Error('请填写空间名和平台工作区标识');
      const response = await ownerApi.POST('/api/owner/v1/workspaces', {
        params: { header: await mutationHeaders() },
        body: { displayName: registerName.trim(), platformWorkspaceId: registerPlatformId.trim() },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      setRegisterOpen(false);
      setRegisterName('');
      setRegisterPlatformId('');
      await queryClient.invalidateQueries({ queryKey: ['workspaces'] });
      message.success('空间已登记。关联母号后开始读取事实。');
    },
    onError: (error) => message.error(errorMessage(error)),
  });

  // ── 动作 ────────────────────────────────────────────────────────────────

  function confirmJoin() {
    if (!batch) return;
    const blockers = joinPreview.data && !joinPreview.data.canProceed ? joinPreview.data.blockers : [];
    modal.confirm({
      title: `确认把 ${batch.targetCount} 个成员加入「${detail.data?.workspace.displayName ?? ''}」？`,
      content: (
        <div className="dialog-body">
          <div>加入前每个账号都会实时检查，检查不过的不会加入。</div>
          <div>加入即开始占用席位，服务期从平台确认加入起算。</div>
          <div>其他空间的批次不受影响。</div>
          {blockers.length > 0 ? (
            <div className="dialog-body__zhu">
              {blockers.map((b) => (
                <div key={b.code}>{b.message}</div>
              ))}
            </div>
          ) : null}
        </div>
      ),
      okText: '确认加入',
      cancelText: '先不加入',
      okButtonProps: { disabled: blockers.length > 0 },
      onOk: () => createJoin.mutate(),
    });
  }

  function confirmRemove() {
    if (!batch) return;
    modal.confirm({
      title: `确认移除「${detail.data?.workspace.displayName ?? ''}」这一批的 ${batch.targetCount} 个成员？`,
      content: (
        <div className="dialog-body">
          <div>移除后，这些成员不再占用席位，这批客户的服务期结束。</div>
          <div>已经下载过交付结果的客户不受影响。</div>
          <div>其他空间的批次不受影响。</div>
        </div>
      ),
      okText: '确认移除',
      cancelText: '先不移除',
      okButtonProps: { danger: true },
      onOk: () => createRemove.mutate(),
    });
  }

  function runAction(kind: ActionKind) {
    switch (kind) {
      case 'reread':
        refreshEvidence.mutate();
        break;
      case 'linkAccount':
        setBindingOpen(true);
        break;
      case 'pickMembers':
        setPickerOpen(true);
        break;
      case 'gotoDelivery':
        navigate('/delivery');
        break;
      case 'join':
        confirmJoin();
        break;
      case 'remove':
        confirmRemove();
        break;
    }
  }

  // ── 渲染 ────────────────────────────────────────────────────────────────

  const memberOutcome = new Map(
    (joinOperation.data?.targets ?? []).map((t) => [t.targetAccountId, t.status]),
  );
  const memberRows = (batchDetail.data?.targets ?? []).map((t) => ({
    key: t.id,
    label: t.displayLabel,
    outcome: joinOutcomeLabel(memberOutcome.get(t.id)),
  }));

  // 逐行日志的 displayLabel 映射：内部 targetAccountId → 可读名（MR-09）
  const labelById = new Map(
    (batchDetail.data?.targets ?? []).map((t) => [t.id, t.displayLabel]),
  );

  // 机队共享刻度：同一屏内所有时间条以最大剩余为基准，因此可以横向比较谁最先到期
  const fleetScale = timeScale(railItems.map((w) => hoursUntil(w.activeUntil)));

  const pickerColumns = [
    {
      title: '成员账号',
      dataIndex: 'displayLabel',
      key: 'label',
      ellipsis: true,
      render: (v: string) => <span className="mono">{v}</span>,
    },
    {
      title: '能不能用',
      dataIndex: 'latestProbeStatus',
      key: 'probe',
      width: 130,
      render: (v: string | undefined) => probePill(v),
    },
  ];

  const runningSpaceId = joinActive || removalActive
    ? (removalActive ? removalOperation.data?.workspaceId : joinOperation.data?.workspaceId)
    : activeRead
      ? selectedId
      : undefined;

  return (
    <OwnerShell>
      <div className="workbench">
        {/* 左栏 · 机队排期表：按剩余时间排序，时间条共享刻度，因此整列可横向比较 */}
        <aside className="rail">
          <div className="block__head">
            <span className="micro">机队 · <span className="num">{workspaces.data?.total ?? '…'}</span></span>
            <Button type="text" size="small" onClick={() => setRegisterOpen(true)}>
              + 登记
            </Button>
          </div>
          <ul className="rail__list">
            {workspaces.isLoading ? <Spin size="small" /> : null}
            {workspaces.isError ? (
              <li className="quietnote">空间列表读取失败：{errorMessage(workspaces.error)}</li>
            ) : null}
            {railItems.map((w) => {
              const facts = railFacts(w);
              const attention = attentionIds.has(w.id) || w.operationalState !== 'operational';
              return (
                <li key={w.id}>
                  <button
                    type="button"
                    className={[
                      'rail__item',
                      attention ? 'rail__item--attention' : '',
                      selectedId === w.id ? 'rail__item--active' : '',
                      w.operationalState === 'deactivated' ? 'rail__ended' : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                    aria-current={selectedId === w.id ? 'true' : undefined}
                    onClick={() => select(w.id)}
                  >
                    <span className="rail__name">{w.displayName}</span>
                    <span className="rail__time">
                      {runningSpaceId === w.id ? (
                        <span className="rail__running">
                          <span className="rail__running-dot" />
                          运行中
                        </span>
                      ) : (
                        <span className={`num${hoursTone(facts.hours) ? ` is-${hoursTone(facts.hours)}` : ''}`}>
                          {facts.hours === undefined ? '—' : facts.hours <= 0 ? '已到' : `${facts.hours}h`}
                        </span>
                      )}
                    </span>
                    <span className="rail__seats">
                      <SeatGrid
                        seatLimit={facts.seatLimit}
                        members={facts.occupied}
                        pending={facts.pending}
                        compact
                      />
                    </span>
                    <span className="rail__bar">
                      <TimeBar hours={facts.hours} scaleHours={fleetScale} showText={false} compact />
                    </span>
                  </button>
                </li>
              );
            })}
            {!workspaces.isLoading && railItems.length === 0 ? (
              <li className="quietnote">
                还没有登记空间。点上方「+ 登记」，把一个团队空间登记进来，再关联它的母号。
              </li>
            ) : null}
          </ul>
        </aside>

        {/* 中栏 · 当前批的生命线 */}
        <main className="flow">
          {!selectedId ? (
            <div className="block">
              <h1 className="block__title">登记第一个空间</h1>
              <p className="block__text">
                左栏「+ 登记」把一个空间登记进来，再关联它的母号。
              </p>
            </div>
          ) : detail.isLoading ? (
            <Spin />
          ) : detail.isError ? (
            <div className="quietnote">空间读取失败：{errorMessage(detail.error)}</div>
          ) : (
            <>
              {/* 身份：这是哪个空间、谁的母号 */}
              <div className="page__head">
                <div>
                  <h1 className="page__title">{detail.data?.workspace.displayName}</h1>
                  <p className="page__sub">
                    {motherName ? <>{motherName} 的空间</> : '还没有关联母号'}
                    {batch ? <> · 第 {batch.sequenceNo} 批</> : null}
                  </p>
                </div>
                <div className="toolbar">
                  <span className="micro">席位</span>
                  <SeatGrid
                    seatLimit={detail.data?.workspace.seatLimit}
                    members={detail.data?.workspace.memberCount}
                    pending={detail.data?.workspace.pendingInviteCount}
                  />
                </div>
              </div>

              {/* 朱批：需要你决断的事。有朱批时下方动作条自动让位，一屏只有一个主按钮 */}
              {zhupi.map((z) => (
                <div className="zhupi" key={z.key}>
                  <span className="zhupi__text">{z.text}</span>
                  {z.action ? (
                    <Button size="small" type="primary" onClick={() => runAction(z.action!.kind)}>
                      {z.action.label}
                    </Button>
                  ) : null}
                </div>
              ))}

              {/* 批次道：五段流程是一条生命线，右端是闸门 */}
              <div className="block">
                <div className="block__head">
                  <h3>这一批的一生</h3>
                  {batch ? (
                    <span className="micro">
                      第 <span className="num">{batch.sequenceNo}</span> 批 ·{' '}
                      {{
                        draft: '筹备中',
                        planned: '已安排',
                        joining: '加入中',
                        serving: '服务中',
                        removing: '移除中',
                        ended: '已结束',
                      }[batch.status] ?? batch.status}
                    </span>
                  ) : null}
                </div>
                <BatchLane
                  cards={cards}
                  hours={batch ? hoursUntil(batch.plannedAt) : undefined}
                  gate={batch && batch.status !== 'ended' ? 'closed' : 'open'}
                />
              </div>

              {action ? (
                <div className="actionbar">
                  <span className="micro">下一步</span>
                  <Button
                    type={action.kind === 'remove' ? 'default' : 'primary'}
                    danger={action.kind === 'remove'}
                    onClick={() => runAction(action.kind)}
                  >
                    {action.label}
                  </Button>
                </div>
              ) : null}

              <Collapse
                ghost
                items={[
                  {
                    key: 'members',
                    label: `成员名单（${batchDetail.data?.targetTotal ?? 0} 个）`,
                    children: memberRows.length > 0 ? (
                      <Table
                        size="small"
                        rowKey="key"
                        pagination={false}
                        columns={[
                          {
                            title: '成员账号',
                            dataIndex: 'label',
                            key: 'label',
                            ellipsis: true,
                            render: (v: string) => <span className="mono">{v}</span>,
                          },
                          {
                            title: '结果',
                            dataIndex: 'outcome',
                            key: 'outcome',
                            width: 120,
                            render: (v: string) => v,
                          },
                        ]}
                        dataSource={memberRows}
                      />
                    ) : (
                      <div className="quietnote">这个空间还没有安排成员。</div>
                    ),
                  },
                  {
                    key: 'capacity',
                    label: '容量明细',
                    children: (
                      <div className="quietnote">
                        席位 <span className="num">{detail.data?.workspace.seatLimit ?? '—'}</span>
                        {detail.data?.workspace.memberCount !== undefined ? (
                          <> · 平台成员 <span className="num">{detail.data.workspace.memberCount}</span></>
                        ) : null}
                        {detail.data?.workspace.pendingInviteCount ? (
                          <> · 待接受 <span className="num">{detail.data.workspace.pendingInviteCount}</span></>
                        ) : null}
                        {seats !== undefined ? <> · 可用 <span className="num">{seats}</span></> : null}
                      </div>
                    ),
                  },
                ]}
              />
            </>
          )}
        </main>

        {/* 右栏 · 运行面板 */}
        <aside className="run">
          <div className="run__head">
            <span className="micro">正在运行</span>
          </div>
          <div className="run__body">
            {removalActive && removalOperation.data ? (
              <RunTask
                name="到期移除"
                spaceName={detail.data?.workspace.displayName}
                succeeded={removalOperation.data.succeededCount}
                blocked={removalOperation.data.blockedCount}
                total={removalOperation.data.targetTotal}
                targets={removalOperation.data.targets}
                labelById={labelById}
              />
            ) : joinActive && joinOperation.data ? (
              <RunTask
                name="批量加入"
                spaceName={detail.data?.workspace.displayName}
                succeeded={joinOperation.data.succeededCount}
                failed={joinOperation.data.failedCount}
                blocked={joinOperation.data.blockedCount}
                total={joinOperation.data.targetTotal}
                targets={joinOperation.data.targets}
                labelById={labelById}
              />
            ) : readActive ? (
              <>
                <div className="run__task">读取成员名单</div>
                <div className="run__space">{detail.data?.workspace.displayName}</div>
                <div className="run__count run__count--gap">
                  正在读取，通常 1–2 分钟
                </div>
              </>
            ) : (
              <div className="run__idle">当前空闲，可启动任务。</div>
            )}
          </div>
        </aside>
      </div>

      {/* 选择本批成员抽屉 */}
      <Drawer
        title="选择本批成员"
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        size={520}
        footer={
          <div className="drawer-foot">
            <span className="quietnote">
              已选 <span className="num">{picked.length}</span> 个
              {seats !== undefined ? <> · 可用席位 <span className="num">{seats}</span> 个</> : null}
            </span>
            <span className="toolbar">
              <Button onClick={() => setPickerOpen(false)}>取消</Button>
              <Button
                type="primary"
                disabled={picked.length === 0}
                loading={saveBatch.isPending}
                onClick={() => saveBatch.mutate()}
              >
                安排批次
              </Button>
            </span>
          </div>
        }
      >
        <div className="settings-field">
          <span className="micro">计划处理时间（到期移除）</span>
          <Input
            id="planned-at"
            name="planned-at"
            type="datetime-local"
            value={plannedAt}
            onChange={(e) => setPlannedAt(e.target.value)}
          />
        </div>
        <p className="quietnote">
          只列出启用的账号；加入前仍会逐个实时检查。
        </p>
        <Table
          size="small"
          rowKey="id"
          pagination={false}
          columns={pickerColumns}
          dataSource={pickerTargets.data?.items ?? []}
          rowSelection={{
            selectedRowKeys: picked,
            onChange: (keys) => {
              const all = keys.map((k) => String(k));
              setPicked(seats === undefined ? all : all.slice(0, seats));
            },
          }}
        />
      </Drawer>

      {/* 关联母号 */}
      <Modal
        title="关联母号"
        open={bindingOpen}
        onCancel={() => setBindingOpen(false)}
        okText="关联"
        cancelText="取消"
        okButtonProps={{ disabled: !motherPick }}
        confirmLoading={createBinding.isPending}
        onOk={() => createBinding.mutate()}
      >
        <p className="quietnote">
          关联后系统会先核对母号能不能管理这个空间，再读取席位和成员。
        </p>
        <Select
          className="control-full"
          placeholder="选择母号"
          value={motherPick}
          onChange={setMotherPick}
          options={(motherAccounts.data ?? [])
            .filter((a) => a.status === 'active')
            .map((a) => ({ value: a.id, label: a.displayName }))}
        />
      </Modal>

      {/* 登记空间 */}
      <Modal
        title="登记空间"
        open={registerOpen}
        onCancel={() => setRegisterOpen(false)}
        okText="登记"
        cancelText="取消"
        confirmLoading={registerWorkspace.isPending}
        onOk={() => registerWorkspace.mutate()}
      >
        <div className="settings-block">
          <div className="settings-field">
            <span className="micro">空间名</span>
            <Input
              id="register-name"
              name="register-name"
              value={registerName}
              onChange={(e) => setRegisterName(e.target.value)}
              placeholder="例如：A 空间"
            />
          </div>
          <div className="settings-field">
            <span className="micro">平台工作区标识</span>
            <Input
              id="register-platform"
              name="register-platform"
              value={registerPlatformId}
              onChange={(e) => setRegisterPlatformId(e.target.value)}
              placeholder="ChatGPT Business 的工作区标识"
            />
          </div>
        </div>
      </Modal>
    </OwnerShell>
  );
}

function RunTask({
  name,
  spaceName,
  succeeded,
  failed,
  blocked,
  total,
  targets,
  labelById,
}: {
  name: string;
  spaceName?: string | undefined;
  succeeded: number;
  failed?: number;
  blocked?: number;
  total: number;
  targets: { targetAccountId: string; status: string; completedAt?: string; lastAttemptAt?: string }[];
  labelById: Map<string, string>;
}) {
  const done = succeeded + (failed ?? 0) + (blocked ?? 0);
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  // 逐行日志：只显示已有结果的目标（等宽小字，内部 ID 映射为 displayLabel）
  const logLines = targets
    .filter((t) => t.status !== 'queued' && t.status !== 'running')
    .map((t) => ({
      label: labelById.get(t.targetAccountId) ?? '成员',
      status: t.status,
      time: t.completedAt ?? t.lastAttemptAt,
    }));

  return (
    <>
      <div className="run__task">{name}</div>
      <div className="run__space">{spaceName}</div>
      <div className="run__progress-row">
        <span className="run__count">
          <span className="num">{done}</span> / <span className="num">{total}</span>
        </span>
      </div>
      <div className="run__bar">
        <div className="run__bar-fill" style={{ '--fill': `${pct}%` } as CSSProperties} />
      </div>
      <div className="run__count run__count--gap">
        成功 <span className="num">{succeeded}</span>
        {failed !== undefined && failed > 0 ? <> · 没加入 <span className="num">{failed}</span></> : null}
        {blocked !== undefined && blocked > 0 ? <> · 待核对 <span className="num">{blocked}</span></> : null}
      </div>
      {logLines.length > 0 ? (
        <div className="run__log">
          {logLines.map((line, i) => (
            <div
              key={`${line.label}-${i}`}
              className={`run__log-line ${
                line.status === 'failed' || line.status === 'blocked' || line.status === 'unknown'
                  ? 'run__log-line--warn'
                  : ''
              }`}
            >
              <span className="run__log-time">
                {line.time ? new Date(line.time).toLocaleTimeString() : '—'}
              </span>
              <span>
                {line.label} {joinOutcomeLabel(line.status)}
              </span>
            </div>
          ))}
        </div>
      ) : null}
    </>
  );
}
