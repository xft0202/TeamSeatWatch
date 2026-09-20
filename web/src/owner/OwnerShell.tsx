import {
  ClockCircleOutlined,
  MenuOutlined,
  PlayCircleOutlined,
  SettingOutlined,
} from '@ant-design/icons';
import { Button, Drawer, Layout, Menu, Typography } from 'antd';
import { useState, type ReactNode } from 'react';
import { useLocation, useNavigate } from 'react-router';

const navigation = [
  { key: '/', icon: <PlayCircleOutlined />, label: '开始操作' },
  { key: '/records', icon: <ClockCircleOutlined />, label: '记录与问题' },
  { key: '/settings', icon: <SettingOutlined />, label: '系统设置' },
];

function contextState(value: string) {
  switch (value) {
    case 'operational': return '当前可运营';
    case 'deactivated': return '已停用';
    case 'not_found': return '团队空间不存在';
    default: return '证据不足';
  }
}

export default function OwnerShell({ children, workspace }: {
  children: ReactNode;
  workspace?: { displayName: string; operationalState: string } | undefined;
}) {
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const selected = location.pathname.startsWith('/records')
    ? '/records'
    : location.pathname.startsWith('/settings') ? '/settings' : '/';
  const menu = (
    <Menu
      mode="inline"
      selectedKeys={[selected]}
      items={navigation}
      onClick={({ key }) => {
        setOpen(false);
        navigate(key);
      }}
    />
  );
  return (
    <Layout className="operations-shell">
      <Layout.Sider width={200} breakpoint="xl" collapsedWidth={64} className="owner-sider">
        <Typography.Text strong className="owner-brand">TSW</Typography.Text>
        {menu}
      </Layout.Sider>
      <Layout>
        <Layout.Header className="operations-header">
          <Button
            className="mobile-menu"
            type="text"
            icon={<MenuOutlined />}
            aria-label="打开导航"
            onClick={() => setOpen(true)}
          />
          <div>
            <Typography.Text strong>当前流程</Typography.Text>
            <Typography.Text type="secondary">
              {workspace ? ` ${workspace.displayName} · ${contextState(workspace.operationalState)}` : ' 尚未选择团队空间'}
            </Typography.Text>
          </div>
        </Layout.Header>
        <Layout.Content className="operations-content">{children}</Layout.Content>
      </Layout>
      <Drawer title="导航" placement="left" open={open} onClose={() => setOpen(false)} size={280}>
        {menu}
      </Drawer>
    </Layout>
  );
}
