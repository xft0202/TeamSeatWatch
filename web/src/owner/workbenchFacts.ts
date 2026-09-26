import type { components } from '../generated/owner';

// 工作台事实推导（规格书 §3.2，票据 08/09）。
// 页面只渲染推导结果；记录页的「还没处理完」复用同一推导，保证两处永远同源。
//
// 信息唯一家（规格书 §11-8）：空间名/母号 → 头部；席位 → 卡 01；批次/成员 → 卡 01/02；
// 加入进度 → 卡 03；交付进度 → 卡 04；剩余时间 → 卡 05；阻塞 → 朱批；动作 → 朱批或动作条。
// 轮转时间一律以小时计；未知 ≠ 失败：未知说「无法确认」。

export type Workspace = components['schemas']['Workspace'];
export type WorkspaceDetail = components['schemas']['WorkspaceDetail'];
export type Batch = components['schemas']['Batch'];
export type JoinOperation = components['schemas']['JoinOperation'];
export type RemovalOperation = components['schemas']['RemovalOperation'];
export type Delivery = components['schemas']['Delivery'];

export const FLOW = ['选择本批成员', '安排批次', '确认加入', '客户交付', '到期移除'] as const;

export type ActionKind =
  | 'linkAccount'
  | 'reread'
  | 'join'
  | 'remove'
  | 'pickMembers'
  | 'gotoDelivery';

export interface Zhupi {
  key: string;
  text: string;
  action: { label: string; kind: ActionKind } | null;
}

export interface FlowCard {
  title: string;
  status: 'done' | 'current' | 'locked' | 'pending';
  line: string;
}

/** 剩余小时（向下取整）；无时间或解析失败返回 undefined。 */
export function hoursUntil(iso: string | undefined, now = Date.now()): number | undefined {
  if (!iso) return undefined;
  const diff = Date.parse(iso) - now;
  if (Number.isNaN(diff)) return undefined;
  return Math.floor(diff / 3_600_000);
}

export function hoursText(h: number | undefined): string {
  if (h === undefined) return '时间未知';
  if (h <= 0) return '时间已到';
  return `剩 ${h} 小时`;
}

export function availableSeats(w: Workspace | undefined): number | undefined {
  if (!w || w.seatLimit === undefined) return undefined;
  const used = (w.memberCount ?? 0) + (w.pendingInviteCount ?? 0);
  return Math.max(0, w.seatLimit - used);
}

/** 仍在进行的批次；ended 视为无批次（进入下一轮选择）。 */
export function activeBatch(items: Batch[] | undefined): Batch | undefined {
  if (!items || items.length === 0) return undefined;
  const active = items.filter((b) => b.status !== 'ended');
  if (active.length === 0) return undefined;
  return [...active].sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt))[0];
}

/**
 * 朱批：有阻塞时的唯一动作入口。
 * 加入结果未知/失败只在加入阶段呈现——进入交付后它是交付页的事实（部分加入语义：
 * 已确认加入的成员继续交付，未知/失败只阻塞换批）。
 */
export function deriveZhupi(args: {
  workspace?: Workspace | undefined;
  bindingExists: boolean;
  batch?: Batch | undefined;
  joinOp?: JoinOperation | undefined;
  now?: number | undefined;
}): Zhupi[] {
  const now = args.now ?? Date.now();
  const out: Zhupi[] = [];
  const w = args.workspace;

  if (!args.bindingExists) {
    out.push({
      key: 'noAccount',
      text: '还没有关联母号，读不到这个空间的席位和成员',
      action: { label: '关联母号', kind: 'linkAccount' },
    });
    return out;
  }

  if (w?.operationalState === 'deactivated') {
    out.push({ key: 'deactivated', text: '平台已停用这个空间，不能加入也不能移除', action: null });
  } else if (w?.operationalState === 'not_found') {
    out.push({
      key: 'not_found',
      text: '平台查不到这个空间，需要先核对一次',
      action: { label: '重新读取名单', kind: 'reread' },
    });
  } else if (w?.operationalState === 'unknown') {
    out.push({
      key: 'unknown_state',
      text: '这个空间能不能运营还没有结论',
      action: { label: '重新读取名单', kind: 'reread' },
    });
  }

  const joining = args.batch?.status === 'planned' || args.batch?.status === 'joining' || args.batch?.status === 'draft';
  if (joining && args.joinOp?.status === 'blocked') {
    out.push({
      key: 'join_blocked',
      text: `${args.joinOp.blockedCount} 个成员是否加入无法确认，这一批不能换下一批`,
      action: { label: '重新读取名单', kind: 'reread' },
    });
  } else if (joining && args.joinOp?.status === 'failed') {
    out.push({
      key: 'join_failed',
      text: `${args.joinOp.failedCount} 个没加入成功，不能交付也不能换下一批`,
      action: { label: '重新读取名单', kind: 'reread' },
    });
  }

  const evidenceHours = hoursUntil(w?.evidenceExpiresAt, now);
  if (evidenceHours !== undefined && evidenceHours <= 0) {
    out.push({
      key: 'evidence_stale',
      text: '成员名单已过期，继续之前先重新读一次',
      action: { label: '重新读取名单', kind: 'reread' },
    });
  }

  return out;
}

/** 五段流程卡：每张卡三行（序号+状态 / 步骤名 / 一行关键数字）。 */
export function deriveFlowCards(args: {
  workspace?: Workspace | undefined;
  bindingExists: boolean;
  batch?: Batch | undefined;
  joinOp?: JoinOperation | undefined;
  removalOp?: RemovalOperation | undefined;
  deliveries?: Delivery[] | undefined;
  now?: number | undefined;
}): FlowCard[] {
  const now = args.now ?? Date.now();
  const cards: FlowCard[] = FLOW.map((title) => ({ title, status: 'pending', line: '—' }));
  const set = (i: number, status: FlowCard['status'], line = '—') => {
    const card = cards[i];
    if (!card) return;
    card.status = status;
    card.line = line;
  };
  const b = args.batch;

  if (!args.bindingExists) {
    set(0, 'current', '未关联母号');
    [1, 2, 3, 4].forEach((i) => set(i, 'locked'));
    return cards;
  }

  if (!b) {
    const seats = availableSeats(args.workspace);
    set(0, 'current', seats === undefined ? '席位待读取' : `可用席位 ${seats}`);
    return cards;
  }

  set(0, 'done', `${b.targetCount} 个成员`);
  set(1, 'done', `第 ${b.sequenceNo} 批 · ${hoursText(hoursUntil(b.plannedAt, now))}`);

  if (b.status === 'planned' || b.status === 'joining' || b.status === 'draft') {
    const joined = args.joinOp?.succeededCount ?? 0;
    const total = args.joinOp?.targetTotal ?? b.targetCount;
    set(2, 'current', `${joined}/${total} 加入`);
    if (args.joinOp && (args.joinOp.status === 'blocked' || args.joinOp.status === 'failed')) {
      set(3, 'locked', '待核对');
      set(4, 'locked', '待核对');
    }
    return cards;
  }

  const joined = args.joinOp?.succeededCount ?? b.targetCount;
  set(2, 'done', `${joined}/${b.targetCount} 加入`);

  if (b.status === 'serving') {
    set(3, 'current', `${args.deliveries?.length ?? 0} 交付`);
    const h = hoursUntil(b.plannedAt, now);
    if (h !== undefined && h <= 0) {
      set(3, 'done', `${args.deliveries?.length ?? 0} 交付`);
      set(4, 'current', '时间已到');
    } else {
      set(4, 'pending', hoursText(h));
    }
    return cards;
  }

  if (b.status === 'removing') {
    set(3, 'done', `${args.deliveries?.length ?? 0} 交付`);
    set(4, 'current', args.removalOp
      ? `${args.removalOp.succeededCount}/${args.removalOp.targetTotal} 移除`
      : '移除中');
    return cards;
  }

  return cards;
}

/**
 * 当前动作：有阻塞时返回 null——动作在朱批里（一屏同一时刻只有一个主按钮）。
 * 加入/移除任务运行中返回 null，运行面板接管。
 */
export function deriveStageAction(args: {
  bindingExists: boolean;
  batch?: Batch | undefined;
  joinOp?: JoinOperation | undefined;
  removalOp?: RemovalOperation | undefined;
  zhupi: Zhupi[];
  now?: number | undefined;
}): { label: string; kind: ActionKind } | null {
  if (args.zhupi.length > 0) return null;
  if (!args.bindingExists) return null;
  const b = args.batch;
  if (!b) return { label: '选择本批成员', kind: 'pickMembers' };

  if (b.status === 'planned' || b.status === 'draft') {
    if (args.joinOp && (args.joinOp.status === 'queued' || args.joinOp.status === 'running')) return null;
    return { label: '确认加入', kind: 'join' };
  }
  if (b.status === 'joining') return null;

  if (b.status === 'serving') {
    const h = hoursUntil(b.plannedAt, args.now ?? Date.now());
    if (h !== undefined && h <= 0) return { label: '去移除', kind: 'remove' };
    return { label: '查看凭据库存', kind: 'gotoDelivery' };
  }
  return null;
}

/** 左栏事实行（工作区级事实；批次事实住在流程卡里）。 */
export function railFacts(w: Workspace): string {
  const parts: string[] = [];
  if (w.seatLimit !== undefined) parts.push(`席位 ${w.seatLimit}`);
  if (w.memberCount !== undefined) parts.push(`成员 ${w.memberCount}`);
  const h = hoursUntil(w.activeUntil);
  if (h !== undefined) parts.push(hoursText(h));
  if (parts.length === 0) return '待读取事实';
  return parts.join(' · ');
}

/** 左栏排序：需要处理的在前，其余按订阅到期升序。 */
export function sortWorkspaces(items: Workspace[], attention: Set<string>): Workspace[] {
  return [...items].sort((a, b) => {
    const ra = attention.has(a.id) || a.operationalState !== 'operational' ? 0 : 1;
    const rb = attention.has(b.id) || b.operationalState !== 'operational' ? 0 : 1;
    if (ra !== rb) return ra - rb;
    const ta = a.activeUntil ? Date.parse(a.activeUntil) : Number.POSITIVE_INFINITY;
    const tb = b.activeUntil ? Date.parse(b.activeUntil) : Number.POSITIVE_INFINITY;
    if (ta !== tb) return ta - tb;
    return a.displayName.localeCompare(b.displayName, 'zh-Hans-CN');
  });
}
