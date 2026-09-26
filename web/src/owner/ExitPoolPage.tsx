import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  App, Button, Drawer, Input, Modal, Select, Spin, Table, Tag,
} from 'antd';
import { useState } from 'react';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import type { components } from '../generated/owner';
import { mutationHeaders, ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure } from './problems';

type ProxyEndpoint = components['schemas']['ProxyEndpoint'];

// 出口池页（规格书 §7 + 系统所有者指示）：代理端点管理。
// 显示每个端点的地址、端口、协议、国家、州、验证时间、状态；
// 支持添加（URL + 标签）、删除、验证（探测出口地区）。

function parseURL(raw: string): { protocol: string; host: string; port: string; username: string; password: string } {
  try {
    const u = new URL(raw);
    return {
      protocol: u.protocol.replace(':', ''),
      host: u.hostname,
      port: u.port || '(默认)',
      username: u.username ? u.username : '—',
      password: u.password ? '••••••' : '—',
    };
  } catch {
    return { protocol: '?', host: raw, port: '?', username: '—', password: '—' };
  }
}

function statusPill(status: string) {
  if (status === 'verified') {
    return <span className="pill pill--ok"><span className="pill__dot" />已验证</span>;
  }
  if (status === 'failed') {
    return <span className="pill pill--zhu"><span className="pill__dot" />失败</span>;
  }
  return <span className="pill pill--amber"><span className="pill__dot" />待验证</span>;
}

function timeLabel(v: string | undefined): string {
  return v ? new Date(v).toLocaleString() : '—';
}

export default function ExitPoolPage() {
  const { message, modal } = App.useApp();
  const queryClient = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [addUrl, setAddUrl] = useState('');
  const [addLabel, setAddLabel] = useState('');

  const pool = useQuery({
    queryKey: ['exit-pool', 'page'],
    refetchInterval: 30_000,
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/exit-pool');
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const endpoints = useQuery({
    queryKey: ['proxy-endpoints'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/proxy-endpoints');
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const addEndpoint = useMutation({
    mutationFn: async () => {
      const response = await ownerApi.POST('/api/owner/v1/proxy-endpoints', {
        params: { header: await mutationHeaders() },
        body: { url: addUrl, ...(addLabel ? { label: addLabel } : {}) },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      setAddOpen(false);
      setAddUrl('');
      setAddLabel('');
      await queryClient.invalidateQueries({ queryKey: ['proxy-endpoints'] });
      message.success('代理端点已添加。');
    },
    onError: (error) => message.error(error instanceof Error ? error.message : '添加失败'),
  });

  const deleteEndpoint = useMutation({
    mutationFn: async (id: string) => {
      const response = await ownerApi.DELETE('/api/owner/v1/proxy-endpoints/{endpointId}', {
        params: { path: { endpointId: id }, header: await mutationHeaders() },
      });
      if (response.error) throw apiFailure(response.error, response.response.status);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['proxy-endpoints'] });
      message.success('代理端点已删除。');
    },
    onError: (error) => message.error(error instanceof Error ? error.message : '删除失败'),
  });

  const verifyEndpoint = useMutation({
    mutationFn: async (id: string) => {
      const response = await ownerApi.POST('/api/owner/v1/proxy-endpoints/{endpointId}', {
        params: { path: { endpointId: id }, header: await mutationHeaders() },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async (data) => {
      await queryClient.invalidateQueries({ queryKey: ['proxy-endpoints'] });
      message.success(`验证完成：${data.country || '?'} ${data.region || ''}`);
    },
    onError: (error) => message.error(error instanceof Error ? error.message : '验证失败'),
  });

  function confirmDelete(row: ProxyEndpoint) {
    modal.confirm({
      title: '删除这个代理端点？',
      content: (
        <div style={{ lineHeight: 1.8 }}>
          <div>{parseURL(row.url).host}:{parseURL(row.url).port}</div>
          <div>删除后正在使用这个端点的任务不受影响，但新任务不会再使用它。</div>
        </div>
      ),
      okText: '确认删除',
      cancelText: '先不',
      okButtonProps: { danger: true },
      onOk: () => deleteEndpoint.mutate(row.id),
    });
  }

  const columns = [
    {
      title: '协议',
      key: 'protocol',
      width: 80,
      render: (_: unknown, row: ProxyEndpoint) => {
        const p = parseURL(row.url);
        return <Tag bordered={false}>{p.protocol}</Tag>;
      },
    },
    {
      title: '地址',
      key: 'host',
      render: (_: unknown, row: ProxyEndpoint) => (
        <span className="mono" style={{ fontSize: 12.5 }}>{parseURL(row.url).host}</span>
      ),
    },
    {
      title: '端口',
      key: 'port',
      width: 80,
      render: (_: unknown, row: ProxyEndpoint) => (
        <span className="mono" style={{ fontSize: 12.5 }}>{parseURL(row.url).port}</span>
      ),
    },
    {
      title: '账号',
      key: 'username',
      width: 100,
      render: (_: unknown, row: ProxyEndpoint) => (
        <span className="mono" style={{ fontSize: 12 }}>{parseURL(row.url).username}</span>
      ),
    },
    {
      title: '密码',
      key: 'password',
      width: 80,
      render: () => <span style={{ color: 'var(--ink-3)' }}>••••</span>,
    },
    {
      title: '国家',
      dataIndex: 'country',
      key: 'country',
      width: 70,
      render: (v: string) => v || '—',
    },
    {
      title: '州/地区',
      dataIndex: 'region',
      key: 'region',
      width: 100,
      render: (v: string) => v || '—',
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (v: string) => statusPill(v),
    },
    {
      title: '验证时间',
      key: 'verified',
      width: 160,
      render: (_: unknown, row: ProxyEndpoint) => (
        <span className="mono" style={{ fontSize: 12, color: 'var(--ink-3)' }}>
          {timeLabel(row.verifiedAt)}
        </span>
      ),
    },
    {
      title: '',
      key: 'actions',
      width: 130,
      render: (_: unknown, row: ProxyEndpoint) => (
        <>
          <Button
            type="link"
            size="small"
            loading={verifyEndpoint.isPending && verifyEndpoint.variables === row.id}
            onClick={() => verifyEndpoint.mutate(row.id)}
          >
            验证
          </Button>
          <Button type="link" size="small" danger onClick={() => confirmDelete(row)}>
            删除
          </Button>
        </>
      ),
    },
  ];

  const items = endpoints.data?.items ?? [];
  const verified = items.filter((i) => i.status === 'verified').length;
  const empty = pool.data?.mode === 'proxy_required' && pool.data?.capacity === 0;

  return (
    <OwnerShell fullBleed>
      <main className="page" style={{ maxWidth: 1160 }}>
        <span className="micro">设置</span>
        <h1 className="page__title">出口池</h1>

        <div className="toolbar">
          <Button
            type="primary"
            size="small"
            icon={<PlusOutlined />}
            onClick={() => setAddOpen(true)}
          >
            添加代理
          </Button>
          <Button
            size="small"
            icon={<ReloadOutlined />}
            onClick={() => {
              void endpoints.refetch();
              void pool.refetch();
            }}
          >
            刷新
          </Button>
          <span style={{ flex: 1 }} />
          <span className="quietnote">
            {items.length > 0 ? (
              <>
                <span className="num">{items.length}</span> 个端点 ·{' '}
                <span className="num">{verified}</span> 个已验证
              </>
            ) : (
              '还没有配置代理端点'
            )}
          </span>
        </div>

        {endpoints.isLoading ? <Spin /> : null}
        {endpoints.isError ? (
          <div className="quietnote">
            代理端点读取失败：{endpoints.error instanceof Error ? endpoints.error.message : '未知错误'}
          </div>
        ) : null}

        {items.length > 0 ? (
          <Table
            size="small"
            rowKey="id"
            pagination={false}
            columns={columns}
            dataSource={items}
          />
        ) : !endpoints.isLoading ? (
          <div className="quietnote" style={{ padding: '24px 0' }}>
            还没有代理端点。点上方「添加代理」把一个 SOCKS5 或 HTTP 代理加进来。
          </div>
        ) : null}

        {/* 池状态 */}
        {pool.data ? (
          <div style={{ marginTop: 24 }}>
            <div className="micro" style={{ marginBottom: 8 }}>池状态</div>
            <div className={`poolbar ${empty ? 'poolbar--empty' : ''}`}>
              <span className="poolbar__label">出口池</span>
              <span className="poolbar__facts">
                可用 <span className="num">{pool.data.available}</span> / 容量{' '}
                <span className="num">{pool.data.capacity}</span>
                {pool.data.inUse > 0 ? (
                  <> · 在用 <span className="num">{pool.data.inUse}</span></>
                ) : ''}
              </span>
            </div>
          </div>
        ) : null}
      </main>

      {/* 添加代理 */}
      <Modal
        title="添加代理"
        open={addOpen}
        onCancel={() => setAddOpen(false)}
        okText="添加"
        cancelText="取消"
        okButtonProps={{ disabled: addUrl.trim().length < 8 }}
        confirmLoading={addEndpoint.isPending}
        onOk={() => addEndpoint.mutate()}
      >
        <div style={{ display: 'grid', gap: 12 }}>
          <div>
            <div className="micro" style={{ marginBottom: 6 }}>代理 URL</div>
            <Input
              id="proxy-url"
              name="proxy-url"
              value={addUrl}
              onChange={(e) => setAddUrl(e.target.value)}
              placeholder="socks5://user:pass@host:port"
            />
          </div>
          <div>
            <div className="micro" style={{ marginBottom: 6 }}>标签（可选）</div>
            <Input
              id="proxy-label"
              name="proxy-label"
              value={addLabel}
              onChange={(e) => setAddLabel(e.target.value)}
              placeholder="例如：美国-洛杉矶"
            />
          </div>
        </div>
      </Modal>
    </OwnerShell>
  );
}
