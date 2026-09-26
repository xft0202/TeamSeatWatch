import { useMutation } from '@tanstack/react-query';
import { Alert, Button, Form, Input } from 'antd';
import { useLocation, useNavigate } from 'react-router';
import { useState } from 'react';
import { clearCsrf, mutationHeaders, ownerApi } from './api';
import { apiFailure, problem } from './problems';

type Credentials = { username: string; password: string };

// 登录页（docs/design/DESIGN.md §20）：印章标记 + 56px 衬线标题 + 墨色药丸按钮。
// 版面的分量来自尺寸与字距（56px / 400 / -0.035em），不加粗、不加装饰。
// 文案说人话：不解释实现，只说明这是什么、要做什么。
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
      navigate('/', { replace: true });
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
    <div className="login-stage">
      <div className="login-card" aria-labelledby="login-title">
        <span className="login-card__glyph" aria-hidden>席</span>

        <h1 className="login-card__title" id="login-title">席位运营</h1>
        <p className="login-card__word">
          <span className="login-card__tick" aria-hidden />
          从席位库存到客户兑换，一条链管到底
        </p>

        {message ? (
          <Alert type="warning" showIcon title={message} className="login-card__alert" />
        ) : null}

        <Form<Credentials>
          layout="vertical"
          requiredMark={false}
          onFinish={(value: Credentials) => {
            setMessage('');
            login.mutate(value);
          }}
        >
          <Form.Item
            label="用户名"
            name="username"
            rules={[{ required: true, message: '请输入用户名' }]}
          >
            <Input autoComplete="username" maxLength={254} autoFocus size="large" />
          </Form.Item>
          <Form.Item
            label="密码"
            name="password"
            rules={[{ required: true, message: '请输入密码' }]}
          >
            <Input.Password autoComplete="current-password" maxLength={1024} size="large" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={login.isPending} block>
            登录
          </Button>
        </Form>

        <p className="login-card__foot">
          数据存放在你自己的数据库；平台调用经由你配置的出口通道。
        </p>
      </div>
    </div>
  );
}
