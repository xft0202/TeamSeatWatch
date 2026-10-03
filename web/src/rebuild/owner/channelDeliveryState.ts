import type { ChannelDeliveryStatus } from './channelDelivery';

export function channelDeliveryLabel(status?: Pick<ChannelDeliveryStatus, 'phase'>): string {
  return ({ pending: '交付包待准备', ready: '待发送', receiving: '接收待核验', received: '待交付回执', partial: '部分待处理', delivered: '已交付', blocked: '原交付待处理' })[status?.phase ?? 'pending'];
}
export function channelReceptionLabel(phase: string): string {
  return ({ pending: '待发送', receipt_pending: '待核验接收', record_pending: '接收记录待处理', received: '渠道已接收' } as Record<string, string>)[phase] ?? '待核验接收';
}
export function channelFinalLabel(phase: string): string {
  return ({ pending: '待交付回执', record_pending: '交付记录待处理', delivered: '已交付' } as Record<string, string>)[phase] ?? '待交付回执';
}
export function channelCanReceive(status: ChannelDeliveryStatus | undefined, writeAllowed: boolean, stopped: boolean): boolean {
  return Boolean(status?.packageId && status.nextAction === 'receive' && writeAllowed && !stopped);
}
