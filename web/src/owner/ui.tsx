// 共享视觉词汇（docs/design/DESIGN.md §6、§11）。
// 只放跨页复用的展示件，不放业务判断——业务推导在 workbenchFacts.ts。
//
// 四个专属原语对应业务里四个真实存在的对象，是本产品区别于通用后台的根本：
//   SeatGrid       席位格 —— 席位是离散可数资产，画出来而不是写数字
//   TimeBar        时间条 —— 时间在烧；同屏共享刻度，因而可以横向比较
//   BatchLane      批次道 —— 五段流程是一条生命线，右端是闸门
//   DeliveryChain  交付链 —— 成员→凭据→卡密→兑换，断在哪一节一眼看到

import type { CSSProperties } from 'react';
import type { FlowCard } from './workbenchFacts';
import { hoursText } from './workbenchFacts';

export function probePill(status: string | undefined) {
  if (status === 'available') {
    return <span className="pill pill--ok"><span className="pill__dot" />可以用</span>;
  }
  if (status === 'credential_invalid' || status === 'definitely_unavailable') {
    return <span className="pill pill--zhu"><span className="pill__dot" />不可用</span>;
  }
  return <span className="pill pill--amber"><span className="pill__dot" />暂无法确认</span>;
}

export function joinOutcomeLabel(status: string | undefined): string {
  switch (status) {
    case 'succeeded': return '已加入';
    case 'failed': return '没加入';
    case 'blocked': return '待核对';
    case 'unknown': return '无法确认';
    case 'queued':
    case 'running': return '进行中';
    default: return '—';
  }
}

// ── 席位格 ────────────────────────────────────────────────────────────────────

// 本业务席位常态 2–100，逐格画出来才数得清。
// 超过 80 格时单格会细到看不清，退回带刻度的比例条——语义不变，只是不再可数。
const MAX_CELLS = 80;

/**
 * 席位格：实心墨 = 已在席位上的成员，浅墨 = 已邀请待接受，描边空 = 空闲。
 * 三态都要画出来——「占着就是钱」这件事必须看得见，不能折叠成一个可用数。
 */
export function SeatGrid({
  seatLimit,
  members,
  pending = 0,
  compact = false,
}: {
  seatLimit: number | undefined;
  members: number | undefined;
  pending?: number | undefined;
  compact?: boolean | undefined;
}) {
  if (seatLimit === undefined || seatLimit <= 0) {
    return <span className="readout readout--empty">席位待读取</span>;
  }

  const on = Math.min(Math.max(members ?? 0, 0), seatLimit);
  const wait = Math.min(Math.max(pending, 0), Math.max(seatLimit - on, 0));
  const free = Math.max(seatLimit - on - wait, 0);
  const summary = `共 ${seatLimit} 席：占用 ${on}，待接受 ${wait}，空闲 ${free}`;
  const size = compact ? ' seatgrid--compact' : '';

  if (seatLimit > MAX_CELLS) {
    return (
      <span
        className={`seatbar${size}`}
        role="img"
        aria-label={summary}
        title={summary}
        style={{ '--on': `${(on / seatLimit) * 100}%`, '--wait': `${(wait / seatLimit) * 100}%` } as CSSProperties}
      >
        <span className="seatbar__track">
          <span className="seatbar__on" />
          <span className="seatbar__wait" />
        </span>
      </span>
    );
  }

  return (
    <span
      className={`seatgrid${size}`}
      role="img"
      aria-label={summary}
      title={summary}
      style={{ '--seats': seatLimit } as CSSProperties}
    >
      {Array.from({ length: seatLimit }, (_, i) => (
        <span
          key={i}
          className={`seatgrid__cell${i < on ? ' is-on' : i < on + wait ? ' is-wait' : ''}`}
        />
      ))}
    </span>
  );
}

// ── 时间条 ────────────────────────────────────────────────────────────────────

/** 剩不到一天就该显眼了——这是展示阈值；真正的阻塞规则在 workbenchFacts/后端。 */
const URGENT_HOURS = 24;

/** 剩余时间的语气：阈值只在这里定义一次，调用方不重复判断。 */
export function hoursTone(hours: number | undefined): '' | 'is-over' | 'is-urgent' {
  if (hours === undefined) return '';
  if (hours <= 0) return 'is-over';
  if (hours <= URGENT_HOURS) return 'is-urgent';
  return '';
}

/**
 * 同屏共享刻度：以一组里最大的剩余小时为基准。
 * 这样同一列的空间时间条长度可以直接横向比较，一眼看出谁最先到期。
 * 这是展示刻度，不是业务事实——业务事实是 workbenchFacts.hoursUntil。
 */
export function timeScale(hours: (number | undefined)[]): number {
  const known = hours.filter((h): h is number => h !== undefined && h > 0);
  return known.length > 0 ? Math.max(...known) : 1;
}

/**
 * 时间条：长度 = 剩余 / 刻度。调用方决定刻度基准——
 * 机队列表传 timeScale(全机队)，单批自己的一生传本批服务窗口。
 */
export function TimeBar({
  hours,
  scaleHours,
  showText = true,
  compact = false,
}: {
  hours: number | undefined;
  scaleHours?: number | undefined;
  showText?: boolean | undefined;
  compact?: boolean | undefined;
}) {
  if (hours === undefined) {
    return <span className="readout readout--empty">时间未知</span>;
  }

  const scale = scaleHours !== undefined && scaleHours > 0 ? scaleHours : Math.max(hours, 1);
  const pct = Math.max(0, Math.min(100, (hours / scale) * 100));
  const tone = hoursTone(hours);

  return (
    <span className={`timebar${compact ? ' timebar--compact' : ''}`} style={{ '--fill': `${pct}%` } as CSSProperties}>
      <span className={`timebar__track${tone ? ` ${tone}` : ''}`} role="img" aria-label={hoursText(hours)} title={hoursText(hours)}>
        <span className="timebar__fill" />
      </span>
      {showText && <span className="timebar__text">{hoursText(hours)}</span>}
    </span>
  );
}

// ── 批次道与闸门 ──────────────────────────────────────────────────────────────

/**
 * 批次道：把五段流程画成一条生命线，而不是五张等价卡片。
 * 左端是选择成员，右端是闸门——当前批全部确认移除之前，下一批只能在闸门外等。
 * 阶段状态直接复用 workbenchFacts.deriveFlowCards 的结果，不另立一套词汇。
 */
export function BatchLane({
  cards,
  hours,
  gate,
}: {
  cards: FlowCard[];
  hours?: number | undefined;
  gate: 'open' | 'closed';
}) {
  return (
    <div className="lane">
      <ol className="lane__track">
        {cards.map((card) => (
          <li key={card.title} className={`lane__seg is-${card.status}`}>
            <span className="lane__node" />
            <span className="lane__title">{card.title}</span>
            <span className="lane__line">{card.line}</span>
          </li>
        ))}
      </ol>
      <div className={`lane__gate is-${gate}`}>
        <span className="lane__gate-bar" />
        <span className="lane__gate-text">
          {gate === 'open' ? '可以安排下一批' : '下一批在此等'}
        </span>
        {hours !== undefined && <span className="lane__gate-hours">{hoursText(hours)}</span>}
      </div>
    </div>
  );
}

// ── 交付链 ────────────────────────────────────────────────────────────────────

export type ChainState = 'ok' | 'break' | 'wait' | 'idle';

/**
 * 交付链：成员 → 凭据 → 卡密 → 兑换。断一节就没货，所以断节必须在链上直接可见，
 * 而不是散在几个状态列里让人自己对。表格里用紧凑形（只有点与连线），详情里带标签。
 */
export function DeliveryChain({
  steps,
  labels = false,
}: {
  steps: { label: string; value?: string | undefined; state: ChainState }[];
  labels?: boolean | undefined;
}) {
  const summary = steps
    .map((s) => `${s.label}${s.value ? ` ${s.value}` : ''}${s.state === 'break' ? '（断）' : ''}`)
    .join(' → ');

  return (
    <span className={`chain${labels ? ' chain--labeled' : ''}`} role="img" aria-label={summary} title={summary}>
      {steps.map((step, i) => (
        <span key={step.label} className="chain__item">
          {i > 0 && <span className={`chain__link is-${steps[i - 1]?.state ?? 'idle'}`} />}
          <span className={`chain__node is-${step.state}`} />
          {labels && (
            <span className="chain__label">
              {step.label}
              {step.value && <em className="chain__value">{step.value}</em>}
            </span>
          )}
        </span>
      ))}
    </span>
  );
}
