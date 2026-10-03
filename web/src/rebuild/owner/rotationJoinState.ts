import type { RotationJoinStatus } from './rotationJoin';

export function rotationJoinPhase(status: RotationJoinStatus): string {
  return {
    not_started: '尚未建立原义务',
    intent_reserved: '原候选与席位已固定',
    join_request_uncertain: '加入请求结果待核实',
    join_request_sent: '加入请求已记录',
    join_accept_uncertain: '接受结果待核实',
    reconcile_required: '等待原空间成员核实',
    blocked: '原义务已阻断，需核实',
    credentials_complete: '成员已核实，凭据已保存',
    usage_ready: '首次用量已保存，可进入交付',
    usage_pending: '首次用量已保存，待处理',
  }[status.phase] || '状态待核实';
}
export function rotationJoinMembership(status: RotationJoinStatus): string {
  return { not_observed: '尚未核实', absent: '未确认成员', unknown: '结果不明', invalid: '成员事实冲突', confirmed: '成员已确认' }[status.membership] || '结果待核实';
}
export function rotationJoinCredentials(status: RotationJoinStatus): string {
  return { missing: '尚未保存', partial: '部分保存', unknown: '结果不明', review_required: '需要人工复核', complete: '完整保存' }[status.credentials] || '状态待核实';
}
export function rotationJoinActionLabel(action: string): string {
  return { run: '执行原义务', verify: '核实原空间成员', save: '保存空间凭据', repair: '按原尝试修复', observe: '核实首次用量', recheck: '重新核实用量' }[action] || '';
}
export function rotationJoinErrorMessage(status?: number): string {
  if (status === 401 || status === 403) return '登录或 Owner 权限已失效，请重新登录后核实原槽。';
  if (status === 409) return '原候选、席位或执行租约已变化；已保留原义务，请刷新状态。';
  return '原义务未完成。请读取同一席位状态，结果不明时进行人工复核。';
}

export function rotationJoinUsage(status: RotationJoinStatus): string {
  return { unobserved: '用量待核实', pending: '用量核实未完成', unknown: '用量不明', positive: '已有使用', zero: '当前窗口为零', shared: '用量范围待核实', stale: '用量需重新核实' }[status.usage] || '用量待核实';
}
