import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import {
  Alert,
  App,
  Button,
  Descriptions,
  Empty,
  Layout,
  Space,
  Spin,
  Tabs,
  Typography,
} from 'antd';
import { LogoutOutlined, StopOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router';
import { useEffect, useState } from 'react';
import type { components } from '../generated/owner';
import { clearCsrf, mutationHeaders, ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure, problem } from './problems';

type OwnerSession = components['schemas']['Session'];

async function refreshSession() {
  const result = await ownerApi.POST('/api/owner/v1/session/refresh', {
    params: { header: await mutationHeaders() },
  });
  if (result.error) throw apiFailure(result.error, result.response.status);
}

export default function SecuritySettings() {
  const navigate = useNavigate();
  const client = useQueryClient();
  const { modal } = App.useApp();
  const [actionMessage, setActionMessage] = useState('');

  const status = useQuery({
    queryKey: ['owner-auth-status'],
    queryFn: async () => {
      await refreshSession();
      const result = await ownerApi.GET('/api/owner/v1/auth-status');
      if (result.error || !result.data) {
        throw apiFailure(result.error, result.response.status);
      }
      return result.data;
    },
  });
  const sessions = useQuery({
    queryKey: ['owner-sessions'],
    queryFn: async () => {
      const result = await ownerApi.GET('/api/owner/v1/sessions');
      if (result.error || !result.data) {
        throw apiFailure(result.error, result.response.status);
      }
      return result.data.sessions;
    },
    enabled: status.isSuccess,
  });

  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const result = await ownerApi.DELETE('/api/owner/v1/sessions/{sessionId}', {
        params: {
          path: { sessionId: id },
          header: await mutationHeaders(),
        },
      });
      if (result.error) throw apiFailure(result.error, result.response.status);
    },
    onSuccess: async (_: void, id: string) => {
      setActionMessage('');
      const current = sessions.data?.some(
        (session: OwnerSession) => session.id === id && session.current,
      );
      if (current) {
        // Revoking the current session is an intentional logout, not a stale-session error.
        clearCsrf();
        client.clear();
        navigate('/login', { replace: true });
        return;
      }
      await client.invalidateQueries({ queryKey: ['owner-sessions'] });
    },
    onError: (error: unknown) => {
      if (problem(error).code === 'csrf_rejected') clearCsrf();
      setActionMessage('无法撤销该会话，请重试。');
    },
  });

  const logout = useMutation({
    mutationFn: async () => {
      const result = await ownerApi.POST('/api/owner/v1/logout', {
        params: { header: await mutationHeaders() },
      });
      if (result.error) throw apiFailure(result.error, result.response.status);
    },
    onSuccess: () => {
      clearCsrf();
      client.clear();
      navigate('/login', { replace: true });
    },
    onError: (error: unknown) => {
      if (problem(error).code === 'csrf_rejected') clearCsrf();
      setActionMessage('无法退出当前会话，请重试。');
    },
  });

  const statusProblem = problem(status.error);
  const sessionsProblem = problem(sessions.error);
  const sessionExpired = statusProblem.status === 401 || sessionsProblem.status === 401;

  // Authentication loss is the only query error that changes routes automatically.
  useEffect(() => {
    if (sessionExpired) {
      clearCsrf();
      client.clear();
      navigate('/login', { replace: true, state: { expired: true } });
    }
  }, [client, navigate, sessionExpired]);

  if (status.isLoading || (status.isSuccess && sessions.isLoading) || sessionExpired) {
    return <div className="settings-loading"><Spin size="large" /></div>;
  }

  const loadFailed = status.isError || sessions.isError;
  return (
    <OwnerShell>
      <Layout.Content className="settings-content">
        <div className="section-heading">
          <Typography.Title level={2}>系统设置</Typography.Title>
          <Button icon={<LogoutOutlined />} onClick={() => logout.mutate()} loading={logout.isPending}>
            退出
          </Button>
        </div>
        {loadFailed ? (
          <Alert
            type="error"
            showIcon
            title="无法载入登录安全设置"
            action={(
              <Button
                size="small"
                onClick={() => {
                  void status.refetch();
                  void sessions.refetch();
                }}
              >
                重试
              </Button>
            )}
          />
        ) : (
          <Tabs
            items={[{
              key: 'security',
              label: '登录安全',
              children: (
                <div className="security-view">
                  {actionMessage && (
                    <Alert
                      type="error"
                      showIcon
                      closable={{ onClose: () => setActionMessage('') }}
                      title={actionMessage}
                    />
                  )}
                  <Descriptions
                    bordered
                    size="small"
                    column={1}
                    title="身份验证状态"
                    items={[
                      { key: 'username', label: '用户名', children: status.data?.username },
                      {
                        key: 'password',
                        label: '密码上次更新',
                        children: status.data
                          ? new Date(status.data.passwordChangedAt).toLocaleString()
                          : '',
                      },
                      {
                        key: 'totp',
                        label: '身份验证器',
                        children: status.data?.totpEnabled ? '已启用' : '未启用',
                      },
                    ]}
                  />
                  <Typography.Title level={3}>活动会话</Typography.Title>
                  <div className="session-list" role="list" aria-label="活动会话">
                    {(sessions.data ?? []).length === 0 ? (
                      <Empty description="没有活动会话" />
                    ) : (sessions.data ?? []).map((session: OwnerSession) => (
                      <div className="session-row" role="listitem" key={session.id}>
                        <div className="session-summary">
                          <Typography.Title level={4}>
                            {session.current ? '当前会话' : '管理端会话'}
                          </Typography.Title>
                          <Space orientation="vertical" size={0}>
                            <Typography.Text type="secondary">
                              最近活动：{new Date(session.lastSeenAt).toLocaleString()}
                            </Typography.Text>
                            <Typography.Text type="secondary">
                              最晚到期：{new Date(session.absoluteExpiresAt).toLocaleString()}
                            </Typography.Text>
                          </Space>
                        </div>
                        <Button
                          danger
                          icon={<StopOutlined />}
                          loading={revoke.isPending && revoke.variables === session.id}
                          disabled={revoke.isPending && revoke.variables !== session.id}
                          onClick={() => modal.confirm({
                            title: session.current ? '退出此会话？' : '撤销此会话？',
                            content: session.current
                              ? '确认后当前登录将立即结束。'
                              : '确认后该会话将立即失效，无法撤销。',
                            okText: session.current ? '退出' : '撤销',
                            cancelText: '取消',
                            okButtonProps: { danger: true },
                            onOk: async () => {
                              try {
                                await revoke.mutateAsync(session.id);
                              } catch {
                                // The mutation renders the stable error; the dialog may close.
                              }
                            },
                          })}
                        >
                          {session.current ? '退出此会话' : '撤销'}
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              ),
            }]}
          />
        )}
      </Layout.Content>
    </OwnerShell>
  );
}
