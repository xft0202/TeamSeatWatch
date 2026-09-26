import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Button, Input, Select, Spin } from 'antd';
import { useEffect, useState } from 'react';
import type { components } from '../generated/owner';
import { mutationHeaders, ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure } from './problems';

type ProxySettings = components['schemas']['ProxySettings'];

// 出口池（规格书 §7 + 票据 10）：代理配置直接存在数据库里，界面改完立即生效，无需重启。
// 字段照参考项目：代理类型 / Host / 端口 / 账号 / 密码 / 国家 / 州 / 会话分钟 / 认证模式 / SOCKS5 列表。
// 密码加密存储且不回显（留空 = 保持原值）。

const PROVIDERS = [
  { value: 'direct', label: '无代理直连' },
  { value: 'cliproxy', label: 'Cliproxy（SOCKS5 直连）' },
  { value: 'b2proxy', label: 'B2Proxy（HTTP，需本机中转）' },
  { value: 'proxy1024', label: '1024Proxy（HTTP，需本机中转）' },
  { value: 'socks5', label: 'SOCKS5 列表（粘贴，一行一个）' },
];

const AUTH_MODES = [
  { value: 'basic', label: 'Basic（裸账号）' },
  { value: 'rotating', label: 'Rotating（每账号独立出口）' },
  { value: 'list', label: '列表（逐条使用）' },
];

export default function ExitPoolPage() {
  const { message } = App.useApp();
  const queryClient = useQueryClient();

  const [provider, setProvider] = useState('direct');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('0');
  const [account, setAccount] = useState('');
  const [password, setPassword] = useState('');
  const [authMode, setAuthMode] = useState('basic');
  const [country, setCountry] = useState('');
  const [state, setState] = useState('');
  const [sessionMinutes, setSessionMinutes] = useState('0');
  const [socks5Text, setSocks5Text] = useState('');
  const [loaded, setLoaded] = useState(false);

  const settings = useQuery({
    queryKey: ['proxy-settings'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/settings/proxy');
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const pool = useQuery({
    queryKey: ['exit-pool', 'page'],
    refetchInterval: 30_000,
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/exit-pool');
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  // 载入一次已保存的配置；密码永不回显，留空表示保持原值。
  useEffect(() => {
    const data = settings.data;
    if (!data || loaded) return;
    setProvider(data.provider ?? 'direct');
    setHost(data.host ?? '');
    setPort(String(data.port ?? 0));
    setAccount(data.account ?? '');
    setAuthMode(data.authMode ?? 'basic');
    setCountry(data.country ?? '');
    setState(data.state ?? '');
    setSessionMinutes(String(data.sessionLifetimeMin ?? 0));
    setSocks5Text((data.socks5List ?? []).join('\n'));
    setLoaded(true);
  }, [settings.data, loaded]);

  const save = useMutation({
    mutationFn: async () => {
      const response = await ownerApi.PUT('/api/owner/v1/settings/proxy', {
        params: { header: await mutationHeaders() },
        body: {
          provider: provider as NonNullable<ProxySettings['provider']>,
          host,
          port: Number(port) || 0,
          account,
          ...(password ? { password } : {}),
          keepPassword: !password,
          authMode: authMode as 'basic' | 'rotating' | 'list',
          country,
          state,
          sessionLifetimeMin: Number(sessionMinutes) || 0,
          socks5List: socks5Text
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.length > 0 && !line.startsWith('#')),
        },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      setPassword('');
      await queryClient.invalidateQueries({ queryKey: ['proxy-settings'] });
      await queryClient.invalidateQueries({ queryKey: ['exit-pool'] });
      message.success('已保存并生效，不需要重启。');
    },
    onError: (error) => message.error(error instanceof Error ? error.message : '保存失败'),
  });

  const current = settings.data;
  const poolData = pool.data;
  const poolEmpty = poolData?.mode === 'proxy_required' && poolData?.capacity === 0;
  const socks5Lines = socks5Text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#')).length;

  return (
    <OwnerShell fullBleed>
      <main className="page" style={{ maxWidth: 860 }}>
        <span className="micro">设置</span>
        <h1 className="page__title">出口池</h1>

        {settings.isLoading ? <Spin /> : null}
        {settings.isError ? (
          <div className="quietnote">
            配置读取失败：{settings.error instanceof Error ? settings.error.message : '未知错误'}
          </div>
        ) : null}

        {settings.data ? (
          <>
            {/* 代理状态 */}
            <div className={`poolbar ${poolEmpty ? 'poolbar--empty' : ''}`}>
              <span className="poolbar__label">代理状态</span>
              <span className="poolbar__facts">
                {poolEmpty ? (
                  '池空 — 平台操作已停止'
                ) : (
                  <>
                    可用 <span className="num">{poolData?.available ?? 0}</span> / 容量{' '}
                    <span className="num">{poolData?.capacity ?? 0}</span>
                    {poolData && poolData.inUse > 0 ? (
                      <> · 在用 <span className="num">{poolData.inUse}</span></>
                    ) : null}
                    {poolData?.validatedAt ? <> · 验证于 {new Date(poolData.validatedAt).toLocaleString()}</> : null}
                  </>
                )}
              </span>
            </div>

            {/* 上游 + 连接方式 */}
            <div className="settings-block">
              <div className="micro">上游代理</div>
              <Select
                style={{ width: '100%' }}
                value={provider}
                onChange={setProvider}
                options={PROVIDERS}
              />
              <p className="quietnote" style={{ marginTop: 6 }}>
                {provider === 'direct'
                  ? '用本机出口 IP 直连平台。高并发下单一 IP 易被限流，仅建议测试或低并发使用。'
                  : provider === 'socks5'
                    ? '粘贴一个或多个 SOCKS5 代理，每行一个。支持 socks5://user:pass@host:port 与 host:port:user:pass。'
                    : '经代理访问平台。保存后系统会重新验证出口，验证不过的任务会失败关闭，不会改用直连。'}
              </p>
            </div>

            {/* 凭据 */}
            {provider === 'socks5' ? (
              <div className="settings-block">
                <div className="micro">SOCKS5 代理列表</div>
                <Input.TextArea
                  id="socks5-list"
                  name="socks5-list"
                  rows={8}
                  className="mono"
                  value={socks5Text}
                  onChange={(e) => setSocks5Text(e.target.value)}
                  placeholder={'socks5://user:pass@host:port\nhost:port:user:pass'}
                />
                <div className="quietnote" style={{ marginTop: 6 }}>
                  当前非空行：<span className="num">{socks5Lines}</span>
                </div>
              </div>
            ) : provider === 'direct' ? null : (
              <div className="settings-block">
                <div className="micro">凭据</div>
                <div className="settings-grid">
                  <label className="settings-field">
                    <span>Host</span>
                    <Input id="proxy-host" name="proxy-host" value={host} onChange={(e) => setHost(e.target.value)} placeholder="us2.cliproxy.io" />
                  </label>
                  <label className="settings-field">
                    <span>端口</span>
                    <Input id="proxy-port" name="proxy-port" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} placeholder="443" />
                  </label>
                  <label className="settings-field">
                    <span>账号</span>
                    <Input id="proxy-account" name="proxy-account" value={account} onChange={(e) => setAccount(e.target.value)} />
                  </label>
                  <label className="settings-field">
                    <span>密码{current?.passwordSet ? '（留空 = 不改）' : ''}</span>
                    <Input.Password
                      id="proxy-password"
                      name="proxy-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder={current?.passwordSet ? '已保存，留空不修改' : ''}
                    />
                  </label>
                  <label className="settings-field">
                    <span>国家</span>
                    <Input id="proxy-country" name="proxy-country" value={country} onChange={(e) => setCountry(e.target.value)} placeholder="US" />
                  </label>
                  <label className="settings-field">
                    <span>州（可空）</span>
                    <Input id="proxy-state" name="proxy-state" value={state} onChange={(e) => setState(e.target.value)} />
                  </label>
                  <label className="settings-field">
                    <span>会话分钟</span>
                    <Input id="proxy-session" name="proxy-session" value={sessionMinutes} onChange={(e) => setSessionMinutes(e.target.value.replace(/\D/g, ''))} />
                  </label>
                  <label className="settings-field">
                    <span>认证模式</span>
                    <Select style={{ width: '100%' }} value={authMode} onChange={setAuthMode} options={AUTH_MODES} />
                  </label>
                </div>
              </div>
            )}

            <div className="toolbar" style={{ marginTop: 20 }}>
              <Button type="primary" loading={save.isPending} onClick={() => save.mutate()}>
                保存并生效
              </Button>
              <Button
                onClick={() => {
                  void settings.refetch();
                  void pool.refetch();
                }}
              >
                刷新状态
              </Button>
              <span style={{ flex: 1 }} />
              <span className="quietnote">
                {current?.updatedAt ? `上次保存：${new Date(current.updatedAt).toLocaleString()}` : ''}
              </span>
            </div>
          </>
        ) : null}
      </main>
    </OwnerShell>
  );
}
