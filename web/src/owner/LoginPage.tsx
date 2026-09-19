import { useMutation } from '@tanstack/react-query';
import {
  Alert,
  Button,
  Form,
  Input,
  Layout,
  Segmented,
  Space,
  Typography,
} from 'antd';
import type { InputRef } from 'antd';
import {
  ArrowLeftOutlined,
  LockOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { useLocation, useNavigate } from 'react-router';
import { useEffect, useRef, useState } from 'react';
import { clearCsrf, mutationHeaders, ownerApi } from './api';
import { apiFailure, problem } from './problems';

type Credentials = { username: string; password: string };
type FactorType = 'totp' | 'recovery_code';

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [credentials, setCredentials] = useState<Credentials>();
  const [factorType, setFactorType] = useState<FactorType>('totp');
  const factorRef = useRef<InputRef>(null);
  const [message, setMessage] = useState(
    location.state ? '登录状态已失效，请重新登录。' : '',
  );

  // Credentials stay only in memory between visual steps and leave the browser once with the factor.
  useEffect(() => {
    if (credentials) factorRef.current?.focus();
  }, [credentials, factorType]);

  const login = useMutation({
    mutationFn: async (factor: string) => {
      if (!credentials) throw new Error('Credentials are unavailable');
      const result = await ownerApi.POST('/api/owner/v1/login', {
        params: { header: await mutationHeaders() },
        body: { ...credentials, factorType, factor },
      });
      if (result.error) throw apiFailure(result.error, result.response.status);
    },
    onSuccess: () => {
      setMessage('');
      navigate('/settings', { replace: true });
    },
    onError: (error: unknown) => {
      const value = problem(error);
      if (value.code === 'csrf_rejected') clearCsrf();
      if (value.status === 429) {
        setMessage(`尝试次数过多，请在 ${value.retryAfterSeconds ?? 900} 秒后重试。`);
      } else if (value.status === 403 || (value.status ?? 0) >= 500) {
        setMessage('登录服务暂时不可用，请稍后重试。');
      } else {
        // The same message covers account, password, TOTP, and recovery-code failures.
        setMessage('用户名、密码或验证码不正确。');
      }
    },
  });

  if (!credentials) {
    return (
      <Layout className="owner-login">
        <Layout.Content className="login-panel" aria-labelledby="login-title">
          <SafetyCertificateOutlined className="login-mark" aria-hidden />
          <Typography.Title id="login-title" level={2}>管理端登录</Typography.Title>
          <Typography.Text type="secondary">TeamSeatWatch</Typography.Text>
          {message && <Alert type="warning" showIcon title={message} />}
          <Form<Credentials>
            layout="vertical"
            requiredMark={false}
            onFinish={(value: Credentials) => {
              setMessage('');
              setCredentials(value);
            }}
          >
            <Form.Item label="用户名" name="username" rules={[{ required: true, message: '请输入用户名' }]}>
              <Input autoComplete="username" prefix={<UserOutlined />} maxLength={254} autoFocus />
            </Form.Item>
            <Form.Item label="密码" name="password" rules={[{ required: true, message: '请输入密码' }]}>
              <Input.Password autoComplete="current-password" prefix={<LockOutlined />} maxLength={1024} />
            </Form.Item>
            <Button type="primary" htmlType="submit" block>继续</Button>
          </Form>
        </Layout.Content>
      </Layout>
    );
  }

  return (
    <Layout className="owner-login">
      <Layout.Content className="login-panel" aria-labelledby="factor-title">
        <Typography.Title id="factor-title" level={2}>验证第二因素</Typography.Title>
        <Typography.Text type="secondary">{credentials.username}</Typography.Text>
        {message && <Alert type="error" showIcon title={message} />}
        <Segmented<FactorType>
          block
          value={factorType}
          options={[
            { label: '身份验证器', value: 'totp' },
            { label: '恢复代码', value: 'recovery_code' },
          ]}
          onChange={(value: FactorType) => {
            setFactorType(value);
            setMessage('');
            login.reset();
          }}
        />
        <Form<{ factor: string }>
          key={factorType}
          layout="vertical"
          requiredMark={false}
          onFinish={({ factor }: { factor: string }) => login.mutate(factor)}
        >
          <Form.Item
            label={factorType === 'totp' ? '6 位验证码' : '一次性恢复代码'}
            name="factor"
            rules={[{ required: true, message: '请输入验证信息' }]}
          >
            <Input
              ref={factorRef}
              autoComplete="one-time-code"
              inputMode={factorType === 'totp' ? 'numeric' : 'text'}
              maxLength={factorType === 'totp' ? 6 : 128}
            />
          </Form.Item>
          <Space orientation="vertical" className="full-width">
            <Button type="primary" htmlType="submit" loading={login.isPending} block>登录</Button>
            <Button
              type="text"
              icon={<ArrowLeftOutlined />}
              onClick={() => {
                setCredentials(undefined);
                setMessage('');
                login.reset();
              }}
              block
            >
              返回
            </Button>
          </Space>
        </Form>
      </Layout.Content>
    </Layout>
  );
}
