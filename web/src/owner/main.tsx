import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router';
import { Appearance } from '../appearance';

const root = document.getElementById('root');
if (!root) throw new Error('Owner root element is missing');

function OwnerUnavailable() {
  return (
    <section className="status-panel" aria-labelledby="owner-status-title">
      <p className="eyebrow">TeamSeatWatch 管理端</p>
      <h1 id="owner-status-title">管理端尚未开放</h1>
      <p>此版本仅提供运行与安全边界。</p>
    </section>
  );
}

function MissingPage() {
  return (
    <section className="status-panel" aria-labelledby="owner-missing-title">
      <h1 id="owner-missing-title">页面不存在</h1>
      <a href="/owner/">返回管理端</a>
    </section>
  );
}

createRoot(root).render(
  <Appearance>
    <QueryClientProvider client={new QueryClient()}>
      <BrowserRouter basename="/owner">
        <div className="app-shell">
          <header className="app-header">TeamSeatWatch</header>
          <main className="app-main">
            <Routes>
              <Route path="/" element={<OwnerUnavailable />} />
              <Route path="*" element={<MissingPage />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  </Appearance>,
);
