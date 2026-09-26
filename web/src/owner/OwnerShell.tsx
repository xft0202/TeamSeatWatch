import { useQuery } from '@tanstack/react-query';
import { useLocation, useNavigate } from 'react-router';
import type { ReactNode } from 'react';
import type { components } from '../generated/owner';
import { ownerApi } from './api';
import { apiFailure } from './problems';

type ExitPoolStatus = components['schemas']['ExitPoolStatus'];

const navigation = [
  { key: '/', label: '工作台' },
  { key: '/accounts', label: '账号' },
  { key: '/delivery', label: '交付' },
  { key: '/records', label: '记录' },
  { key: '/exitpool', label: '设置' },
];

// 顶栏壳（docs/design/DESIGN.md §4、§6）：五个工作入口 + 出口池常驻状态。
// 导航是文字，不用图标——图标需要学习成本。
// 当前页用墨色实底标识，不是下划线。
//
// 出口池状态必须常驻可见：它是「平台操作能不能进行」的总开关。
// 池空时显示朱色「平台操作已停止」——这是全站唯一有权常驻的朱色信号。
export default function OwnerShell({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const selected =
    navigation.find((item) => item.key !== '/' && location.pathname.startsWith(item.key))?.key ??
    '/';

  const pool = useQuery({
    queryKey: ['exit-pool'],
    refetchInterval: 30_000,
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/exit-pool');
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  return (
    <div className="ink-shell">
      <header className="ink-topbar">
        <span className="ink-topbar__brand">
          <span className="ink-topbar__mark" aria-hidden>席</span>
          <span className="ink-topbar__name">TeamSeatWatch</span>
        </span>
        <nav className="ink-topbar__nav" aria-label="主要入口">
          {navigation.map((item) => (
            <button
              key={item.key}
              type="button"
              className={`ink-topbar__link${selected === item.key ? ' is-active' : ''}`}
              aria-current={selected === item.key ? 'page' : undefined}
              onClick={() => navigate(item.key)}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <span className="ink-topbar__spacer" />
        <PoolPill pool={pool.data} onClick={() => navigate('/exitpool')} />
      </header>
      <div className="ink-body">{children}</div>
    </div>
  );
}

function PoolPill({ pool, onClick }: {
  pool: ExitPoolStatus | undefined;
  onClick: () => void;
}) {
  if (!pool) {
    return (
      <button type="button" className="poolpill poolpill--unknown" onClick={onClick}>
        <span className="poolpill__dot" />
        出口池
      </button>
    );
  }
  const empty = pool.mode === 'proxy_required' && pool.capacity === 0;
  const low = pool.mode === 'proxy_required' && pool.available <= 1 && !empty;
  const className = empty ? 'poolpill--empty' : low ? 'poolpill--low' : '';
  return (
    <button type="button" className={`poolpill ${className}`} onClick={onClick}>
      <span className="poolpill__dot" />
      {empty ? (
        '平台操作已停止'
      ) : (
        <>
          出口 <span className="num">{pool.available}</span>/
          <span className="num">{pool.capacity}</span>
        </>
      )}
    </button>
  );
}
