import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router';
import { Appearance } from '../appearance';

const root = document.getElementById('root');
if (!root) throw new Error('Public root element is missing');

function PublicUnavailable() {
  return (
    <section className="status-panel" aria-labelledby="public-status-title">
      <p className="eyebrow">TeamSeatWatch 兑换端</p>
      <h1 id="public-status-title">兑换服务尚未开放</h1>
      <p>当前版本暂不接受卡密。</p>
    </section>
  );
}

function MissingPage() {
  return (
    <section className="status-panel" aria-labelledby="public-missing-title">
      <h1 id="public-missing-title">页面不存在</h1>
      <a href="/redeem/">返回兑换端</a>
    </section>
  );
}

createRoot(root).render(
  <Appearance>
    <QueryClientProvider client={new QueryClient()}>
      <BrowserRouter basename="/redeem">
        <div className="app-shell">
          <header className="app-header">TeamSeatWatch</header>
          <main className="app-main">
            <Routes>
              <Route path="/" element={<PublicUnavailable />} />
              <Route path="*" element={<MissingPage />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  </Appearance>,
);
