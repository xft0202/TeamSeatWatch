import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { App, ConfigProvider, Spin } from 'antd';
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from 'react-router';
import { lazy, Suspense } from 'react';
import { Appearance } from '../appearance';
import { inkLedgerTheme } from './theme';
// 自托管字体（票据 09）：宋体标题＋等宽数字，不走 CDN
import '@fontsource/noto-serif-sc/400.css';
import '@fontsource/noto-serif-sc/500.css';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import './style.css';
import './ink.css';

const LoginPage = lazy(() => import('./LoginPage'));
const WorkbenchPage = lazy(() => import('./WorkbenchPage'));
const RecordsPage = lazy(() => import('./RecordsPage'));
const AccountsPage = lazy(() => import('./AccountsPage'));
const DeliveryPage = lazy(() => import('./DeliveryPage'));
const ExitPoolPage = lazy(() => import('./ExitPoolPage'));

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
});

function RouteLoading() {
  return <div className="settings-loading"><Spin size="large" /></div>;
}

const root = document.getElementById('root');
if (!root) throw new Error('Owner root element is missing');
createRoot(root).render(
  <Appearance>
    <ConfigProvider theme={inkLedgerTheme} button={{ autoInsertSpace: false }}>
      <App>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter basename="/owner">
          <Suspense fallback={<RouteLoading />}>
            <Routes>
              <Route path="/" element={<WorkbenchPage />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/accounts" element={<AccountsPage />} />
              <Route path="/delivery" element={<DeliveryPage />} />
              <Route path="/records" element={<RecordsPage />} />
              <Route path="/exitpool" element={<ExitPoolPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </QueryClientProvider>
      </App>
    </ConfigProvider>
  </Appearance>,
);
