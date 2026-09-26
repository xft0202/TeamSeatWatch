import type { ThemeConfig } from 'antd';

// 纸墨台账 · 设计令牌（规格书 §8，票据 08）。
// 纸 = 底，墨 = 结构（含主按钮），朱 = 批注（全界面只有它有权打断你）。
// 纵深靠三级背景分层（纸→面→嵌套面），静态零阴影；色彩只用于功能强调。
export const ink = {
  paper: '#faf9f5',
  surface: '#fffefb',
  nested: '#f3f1ea',
  ink: '#1c1917',
  ink2: '#57534e',
  ink3: '#8c867c',
  line: 'rgba(71, 67, 42, 0.18)',
  lineStrong: 'rgba(71, 67, 42, 0.34)',
  zhu: '#c14a28',
  zhuWash: '#f9efe7',
  zhuInk: '#8f3a1e',
  ok: '#2f6b4f',
  okWash: '#eef3ec',
  amber: '#a8630a',
  amberWash: '#f7efe0',
} as const;

const sansStack =
  "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif";

// antd 只做令牌映射；形状（药丸按钮、表格底纹、宋体弹窗标题）统一在 ink.css 覆写。
export const inkLedgerTheme: ThemeConfig = {
  token: {
    colorPrimary: ink.ink,
    colorInfo: ink.ink,
    colorError: ink.zhu,
    colorWarning: ink.amber,
    colorSuccess: ink.ok,
    colorText: ink.ink,
    colorTextSecondary: ink.ink2,
    colorTextTertiary: ink.ink3,
    colorBgLayout: ink.paper,
    colorBgContainer: ink.surface,
    colorBgElevated: ink.surface,
    colorBorder: ink.line,
    colorBorderSecondary: ink.line,
    borderRadius: 8,
    controlHeight: 34,
    fontSize: 14,
    fontFamily: sansStack,
    wireframe: false,
  },
  components: {
    Table: {
      headerBg: ink.nested,
      headerColor: ink.ink3,
      borderColor: ink.line,
    },
    Modal: { titleFontSize: 16 },
    Drawer: { paddingLG: 20 },
  },
};
