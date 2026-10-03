import type { BatchZIPStatus } from './batchZIP';

export function batchZIPLabel(status?: BatchZIPStatus): string {
  if (!status) return '正在读取';
  return { pending: '待核实', prepared: '待交付', reserved: '待交付', delivered: '已交付' }[status.phase];
}
export function batchZIPCanGenerate(status?: BatchZIPStatus): boolean {
  return Boolean(status?.phase === 'pending' && status.canGenerate && status.nextAction === 'generate');
}
export function batchZIPDownloadURL(previewId: string): string {
  return `/api/owner/v1/expiry-rotation/previews/${encodeURIComponent(previewId)}/batch-zip/download`;
}
