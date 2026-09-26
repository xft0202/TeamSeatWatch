import type { ThemeConfig } from 'antd';

// 席位运营控制台 · 设计令牌（docs/design/DESIGN.md §3–5）。
//
// 三级表面：纸（画布）→ 面（卡片）→ 嵌套面（表头/日志）。
// 层次靠表面差 + 暖调阴影，不靠边框。色彩只用于状态与决断，绝不装饰。
//
// 这是全站唯一的颜色/间距/字号来源：页面组件里不出现色值，需要新令牌先加在这里。

export const ink = {
  // 表面
  paper: '#faf9f5',
  surface: '#ffffff',
  nested: '#f4f2ec',
  inkBlock: '#1c1b17',

  // 文字（暖调，刻意避开纯黑与冷灰）
  ink: '#16150f',
  ink2: '#4a4741',
  ink3: '#7d7970',
  ink4: '#a8a49a',

  // 朱：全界面唯一有权打断用户的颜色
  zhu: '#c14a28',
  zhuWash: '#f7ece6',
  zhuInk: '#8f3a1e',

  // 状态（只表示状态，不做装饰）
  ok: '#2f6b4f',
  okWash: '#eaf3ee',
  warn: '#a8630a',
  warnWash: '#fbf3e4',

  // 发丝线：最后手段，优先用间距或阴影分隔
  line: '#e8e5dd',
  lineStrong: '#d5d1c5',
} as const;

/** 暖调阴影：用 rgba(22,21,15,…) 而非纯黑，否则在暖纸上显脏。全场只有两级。 */
export const elevation = {
  rest: '0 1px 2px rgba(22, 21, 15, .05), 0 1px 3px rgba(22, 21, 15, .04)',
  raised: '0 4px 16px -4px rgba(22, 21, 15, .08), 0 2px 6px -2px rgba(22, 21, 15, .05)',
  overlay: '0 16px 40px -12px rgba(22, 21, 15, .14), 0 4px 12px -4px rgba(22, 21, 15, .08)',
} as const;

/** 间距尺度（8 的倍数；20 用于卡片内边距）。 */
export const space = {
  xs: 4,
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  xxl: 24,
  block: 32,
  section: 48,
} as const;

/** 圆角上限 12px：大圆角属于消费级产品。 */
export const radius = { card: 10, control: 8, pill: 999 } as const;

const serifStack = "'Noto Serif SC', 'Songti SC', 'SimSun', Georgia, serif";
const monoStack = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
const sansStack =
  "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif";

// 三个声部（DESIGN.md §4）：宋管表达（题、正文），黑管结构（表格、控件），等宽管数据（一切数字）。
export const font = { serif: serifStack, sans: sansStack, mono: monoStack } as const;

// antd 只做令牌映射；形状（药丸按钮、宋体标题、表格底纹）统一在 ink.css 覆写。
export const inkLedgerTheme: ThemeConfig = {
  token: {
    colorPrimary: ink.ink,
    colorInfo: ink.ink,
    colorError: ink.zhu,
    colorWarning: ink.warn,
    colorSuccess: ink.ok,
    colorText: ink.ink,
    colorTextSecondary: ink.ink2,
    colorTextTertiary: ink.ink3,
    colorTextQuaternary: ink.ink4,
    colorBgLayout: ink.paper,
    colorBgContainer: ink.surface,
    colorBgElevated: ink.surface,
    colorBorder: ink.line,
    colorBorderSecondary: ink.line,
    borderRadius: radius.control,
    borderRadiusLG: radius.card,
    controlHeight: 32,
    fontSize: 13,
    fontFamily: sansStack,
    wireframe: false,
  },
  components: {
    Table: {
      headerBg: ink.nested,
      headerColor: ink.ink3,
      borderColor: ink.line,
      rowHoverBg: ink.nested,
      cellPaddingBlock: 10,
      cellPaddingInline: 12,
    },
    Modal: { titleFontSize: 20 },
    Drawer: { paddingLG: space.xxl },
    Button: { defaultBorderColor: ink.lineStrong },
    Input: { activeShadow: 'none' },
    Select: { optionSelectedBg: ink.nested },
  },
};
