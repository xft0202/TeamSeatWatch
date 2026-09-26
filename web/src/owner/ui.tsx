// 共享 UI 片段（规格书 §9：徽章 = 浅底 + 描边 + 深字三件套）。
// 只放跨页复用的小件，不放业务判断——业务推导在 workbenchFacts.ts。

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
