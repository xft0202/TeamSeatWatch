import { useMutation } from '@tanstack/react-query';
import {
  Alert,
  Button,
  Form,
  Input,
  Layout,
  Typography,
} from 'antd';
import {
  LockOutlined,
  SafetyCertificateOutlined,
  UserOutlined,
} from '@ant-design/icons';
import { useLocation, useNavigate } from 'react-router';
import { useState } from 'react';
import { clearCsrf, mutationHeaders, ownerApi } from './api';
import { apiFailure, problem } from './problems';

type Credentials = { username: string; password: string };

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [message, setMessage] = useState(
    location.state ? '登录状态已失效，请重新登录。' : '',
  );

  const login = useMutation({
    mutationFn: async (credentials: Credentials) => {
      const result = await ownerApi.POST('/api/owner/v1/login', {
        params: { header: await mutationHeaders() },
        body: credentials,
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
        setMessage('用户名或密码不正确。');
      }
    },
  });

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
            login.mutate(value);
          }}
        >
          <Form.Item label="用户名" name="username" rules={[{ required: true, message: '请输入用户名' }]}>
            <Input autoComplete="username" prefix={<UserOutlined />} maxLength={254} autoFocus />
          </Form.Item>
          <Form.Item label="密码" name="password" rules={[{ required: true, message: '请输入密码' }]}>
            <Input.Password autoComplete="current-password" prefix={<LockOutlined />} maxLength={1024} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={login.isPending} block>登录</Button>
        </Form>
      </Layout.Content>
    </Layout>
  );
}
