import { useQuery } from '@tanstack/react-query';
import { Collapse, Spin } from 'antd';
import OwnerShell from './OwnerShell';
import { ownerApi } from './api';
import { apiFailure } from './problems';

// 出口池页（规格书 §7）：设置的全部内容。
// 三条从参考项目验证过的做法：数量永远可见、补位状态明确、池空是明确结论。
// 永不显示：端点、IP、协议、指纹、代际、租约（MR-09）。
export default function ExitPoolPage() {
  const pool = useQuery({
    queryKey: ['exit-pool', 'page'],
    refetchInterval: 30_000,
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/exit-pool');
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const empty = pool.data?.mode === 'proxy_required' && pool.data?.capacity === 0;
  const validatedAt = pool.data?.validatedAt
    ? new Date(pool.data.validatedAt).toLocaleString()
    : '未知';

  return (
    <OwnerShell fullBleed>
      <main className="page" style={{ maxWidth: 760 }}>
        <span className="micro">设置</span>
        <h1 className="page__title">出口池</h1>

        {pool.isLoading ? <Spin /> : null}
        {pool.isError ? (
          <div className="quietnote">
            出口池读取失败：{pool.error instanceof Error ? pool.error.message : '未知错误'}
          </div>
        ) : null}

        {pool.data ? (
          <>
            <div className={`poolbar ${empty ? 'poolbar--empty' : ''}`}>
              <span className="poolbar__label">出口池</span>
              {empty ? (
                <>
                  <span className="poolbar__facts">池空 — 平台操作已停止</span>
                </>
              ) : (
                <>
                  <span className="poolbar__facts">
                    可用 <span className="num">{pool.data.available}</span> / 容量{' '}
                    <span className="num">{pool.data.capacity}</span>
                    {pool.data.inUse > 0 ? (
                      <>
                        {' '}· 在用 <span className="num">{pool.data.inUse}</span>
                      </>
                    ) : ''}
                  </span>
                </>
              )}
            </div>

            <Collapse
              ghost
              className="detail-collapse"
              style={{ marginTop: 16 }}
              items={[
                {
                  key: 'detail',
                  label: '明细',
                  children: (
                    <div className="quietnote" style={{ lineHeight: 2.1 }}>
                      <div>
                        可用 <span className="num">{pool.data.available}</span>
                        {' '}· 在用 <span className="num">{pool.data.inUse}</span>
                        {' '}· 容量 <span className="num">{pool.data.capacity}</span>
                        {pool.data.failureCount !== undefined && pool.data.failureCount > 0 ? (
                          <>
                            {' '}· 验证失败 <span className="num">{pool.data.failureCount}</span>
                          </>
                        ) : ''}
                      </div>
                      <div>验证时间：{validatedAt}</div>
                      <div>
                        {pool.data.mode === 'proxy_required'
                          ? '必须使用出口通道。没有可用通道时暂停平台操作，不会改用直连。'
                          : '当前直连模式，不使用出口通道。'}
                      </div>
                    </div>
                  ),
                },
              ]}
            />
          </>
        ) : null}
      </main>
    </OwnerShell>
  );
}
