import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Button, Input, Modal, Spin, Table } from 'antd';
import { useState } from 'react';
import type { components } from '../generated/owner';
import { mutationHeaders, ownerApi } from './api';
import OwnerShell from './OwnerShell';
import { apiFailure } from './problems';
import { probePill } from './ui';

type TargetAccountImportRow = components['schemas']['TargetAccountImportRow'];

// 账号页（规格书 §4）：成员账号用来加入空间、占用席位；母号用来管理空间。
// 导入必须先预览再确认（重复项确认后覆盖）；检查是只读探测，结果带时间。

export default function AccountsPage() {
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<'member' | 'mother'>('member');
  const [importOpen, setImportOpen] = useState(false);
  const [importText, setImportText] = useState('');
  const [picked, setPicked] = useState<string[]>([]);

  const targets = useQuery({
    queryKey: ['target-accounts', 'page'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/target-accounts', {
        params: { query: { page: 1, page_size: 100, sort: 'identifier_asc' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const mothers = useQuery({
    queryKey: ['mother-accounts'],
    queryFn: async () => {
      const response = await ownerApi.GET('/api/owner/v1/mother-accounts', {
        params: { query: { page: 1, page_size: 100, sort: 'name_asc' } },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
  });

  const importPreview = useMutation({
    mutationFn: async () => {
      const response = await ownerApi.POST('/api/owner/v1/target-accounts/import-preview', {
        params: { header: await mutationHeaders() },
        body: { content: importText },
      });
      if (response.error || !response.data) {
        throw apiFailure(response.error, response.response.status);
      }
      return response.data;
    },
    onError: (error) => {
      // 解析失败必须说清原因：格式、重复行、缺密码都是可修的输入错误（不再静默）
      const detail = error as { body?: { detail?: string } };
      message.error(detail.body?.detail ?? '导入内容无法解析，请检查格式。');
    },
  });

  const doImport = useMutation({
    mutationFn: async () => {
      const response = await ownerApi.POST('/api/owner/v1/target-accounts/import', {
        params: { header: await mutationHeaders() },
        body: { content: importText },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async (data) => {
      setImportOpen(false);
      setImportText('');
      importPreview.reset();
      await queryClient.invalidateQueries({ queryKey: ['target-accounts'] });
      message.success(`导入完成：新建 ${data.created} 个，覆盖已存在 ${data.existing} 个。`);
    },
    onError: (error) => message.error(error instanceof Error ? error.message : '导入失败'),
  });

  const probe = useMutation({
    mutationFn: async () => {
      const response = await ownerApi.POST('/api/owner/v1/target-account-probes', {
        params: { header: await mutationHeaders() },
        body: { idempotencyKey: crypto.randomUUID(), targetAccountIds: picked },
      });
      if (response.error || !response.data) throw apiFailure(response.error, response.response.status);
      return response.data;
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['target-accounts'] });
      message.success('检查已排队，完成后这里的「能不能用」会更新。');
    },
    onError: (error) => message.error(error instanceof Error ? error.message : '检查排队失败'),
  });

  const memberColumns = [
    {
      title: '成员账号',
      dataIndex: 'displayLabel',
      key: 'label',
      ellipsis: true,
      render: (v: string) => <span className="mono" style={{ fontSize: 12.5 }}>{v}</span>,
    },
    {
      title: '能不能用',
      dataIndex: 'latestProbeStatus',
      key: 'probe',
      width: 130,
      render: (v: string | undefined) => probePill(v),
    },
    {
      title: '上次检查',
      dataIndex: 'latestProbedAt',
      key: 'probed',
      width: 170,
      render: (v: string | undefined) => (
        <span className="mono" style={{ fontSize: 12, color: 'var(--ink-3)' }}>
          {v ? new Date(v).toLocaleString() : '尚未检查'}
        </span>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) =>
        v === 'active' ? (
          <span className="pill pill--neutral">启用</span>
        ) : (
          <span className="pill pill--zhu"><span className="pill__dot" />停用</span>
        ),
    },
  ];

  const motherColumns = [
    {
      title: '母号',
      dataIndex: 'displayName',
      key: 'name',
      ellipsis: true,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 90,
      render: (v: string) =>
        v === 'active' ? (
          <span className="pill pill--neutral">启用</span>
        ) : (
          <span className="pill pill--zhu"><span className="pill__dot" />停用</span>
        ),
    },
  ];

  const preview = importPreview.data;

  return (
    <OwnerShell fullBleed>
      <main className="page">
        <span className="micro">账号</span>
        <h1 className="page__title">账号</h1>

        <div className="toolbar">
          <Button
            size="small"
            type={kind === 'member' ? 'primary' : 'default'}
            onClick={() => setKind('member')}
          >
            成员账号
          </Button>
          <Button
            size="small"
            type={kind === 'mother' ? 'primary' : 'default'}
            onClick={() => setKind('mother')}
          >
            母号
          </Button>
          <span style={{ flex: 1 }} />
          {kind === 'member' ? (
            <>
              <Button size="small" onClick={() => setImportOpen(true)}>
                导入账号
              </Button>
              <Button
                size="small"
                disabled={picked.length === 0}
                loading={probe.isPending}
                onClick={() => probe.mutate()}
              >
                检查选中的{picked.length > 0 ? `（${picked.length}）` : ''}
              </Button>
            </>
          ) : null}
        </div>

        {kind === 'member' ? (
          targets.isLoading ? (
            <Spin />
          ) : targets.isError ? (
            <div className="quietnote">
              账号列表读取失败：{targets.error instanceof Error ? targets.error.message : '未知错误'}
            </div>
          ) : (
            <Table
              size="small"
              rowKey="id"
              pagination={false}
              columns={memberColumns}
              dataSource={targets.data?.items ?? []}
              rowSelection={{
                selectedRowKeys: picked,
                onChange: (keys) => setPicked(keys.map((k) => String(k))),
              }}
            />
          )
        ) : mothers.isLoading ? (
          <Spin />
        ) : mothers.isError ? (
          <div className="quietnote">
            母号列表读取失败：{mothers.error instanceof Error ? mothers.error.message : '未知错误'}
          </div>
        ) : (
          <Table size="small" rowKey="id" pagination={false} columns={motherColumns} dataSource={mothers.data?.items ?? []} />
        )}
      </main>

      <Modal
        title="导入账号"
        open={importOpen}
        onCancel={() => {
          setImportOpen(false);
          importPreview.reset();
        }}
        footer={
          <>
            <Button
              onClick={() => {
                setImportOpen(false);
                importPreview.reset();
              }}
            >
              取消
            </Button>
            {preview ? (
              <Button type="primary" loading={doImport.isPending} onClick={() => doImport.mutate()}>
                确认导入
              </Button>
            ) : (
              <Button
                type="primary"
                disabled={importText.trim().length === 0}
                loading={importPreview.isPending}
                onClick={() => importPreview.mutate()}
              >
                预览导入
              </Button>
            )}
          </>
        }
      >
        <p className="quietnote" style={{ marginTop: 0 }}>
          一行一个账号，格式：账号----密码----验证密钥
          <br />
          空行和 # 开头的行会跳过。
        </p>
        <Input.TextArea
          id="import-text"
          name="import-text"
          rows={7}
          value={importText}
          onChange={(e) => {
            setImportText(e.target.value);
            importPreview.reset();
          }}
          placeholder={
            'doles_verve_1b@icloud.com----doles_verve_1b----KTELQCCJV7KMDCKE4A4ZEITJFEUAPPLO'
          }
        />
        {preview ? (
          <div style={{ marginTop: 14 }}>
            <div className="quietnote">
              共 <span className="num">{preview.total}</span> 行 · 新建{' '}
              <span className="num">{preview.newCount}</span> · 已存在{' '}
              <span className="num">{preview.existingCount}</span>（确认导入后覆盖）
            </div>
            <Table<TargetAccountImportRow>
              size="small"
              rowKey="line"
              pagination={false}
              style={{ marginTop: 8 }}
              dataSource={preview.items}
              columns={[
                {
                  title: '账号',
                  dataIndex: 'displayLabel',
                  key: 'label',
                  ellipsis: true,
                  render: (v: string) => <span className="mono" style={{ fontSize: 12.5 }}>{v}</span>,
                },
                {
                  title: '密码',
                  dataIndex: 'hasPassword',
                  key: 'password',
                  width: 80,
                  render: (v: boolean) => (v ? '有' : '缺'),
                },
                {
                  title: '验证密钥',
                  dataIndex: 'hasTotp',
                  key: 'totp',
                  width: 90,
                  render: (v: boolean) => (v ? '有' : '缺'),
                },
                {
                  title: '重复',
                  dataIndex: 'existing',
                  key: 'existing',
                  width: 90,
                  render: (v: boolean) =>
                    v ? <span className="pill pill--amber">已存在</span> : <span className="pill pill--ok">新建</span>,
                },
              ]}
            />
          </div>
        ) : null}
      </Modal>
    </OwnerShell>
  );
}
