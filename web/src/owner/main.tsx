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
import './style.css';

const LoginPage = lazy(() => import('./LoginPage'));
const SecuritySettings = lazy(() => import('./SecuritySettings'));

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
    <ConfigProvider
      theme={{
        // Owner controls use higher-contrast product tokens; the public bundle stays independent.
        token: {
          colorPrimary: '#0958D9',
          colorError: '#B42318',
          colorTextSecondary: '#344054',
          colorTextDescription: '#344054',
          colorTextTertiary: '#344054',
          borderRadius: 6,
        },
      }}
    >
      <App>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter basename="/owner">
          <Suspense fallback={<RouteLoading />}>
            <Routes>
              <Route path="/" element={<Navigate to="/login" replace />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/settings" element={<SecuritySettings />} />
              <Route path="*" element={<Navigate to="/login" replace />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </QueryClientProvider>
      </App>
    </ConfigProvider>
  </Appearance>,
);
