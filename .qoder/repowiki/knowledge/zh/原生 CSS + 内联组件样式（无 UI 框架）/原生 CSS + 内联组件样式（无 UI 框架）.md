---
kind: frontend_style
name: 原生 CSS + 内联组件样式（无 UI 框架）
category: frontend_style
scope:
    - '**'
source_files:
    - src/styles.css
    - src/App.tsx
    - index.html
---

本仓库的前端样式采用纯原生 CSS + React 函数式组件方案，未引入任何 UI 组件库、CSS-in-JS 或原子化框架。样式集中在单一文件 src/styles.css，通过全局 :root 变量定义主题色与字体，所有视觉表现由该文件中的 BEM 风格类名驱动。

- 样式组织方式：单文件集中管理，按功能模块划分区块（shell/aside/main、hero/stats、panel/log-table、modal 等），使用语义化 class 命名（如 .proxy-node、.sub-proxy-group-btn、.recommended-source-card），遵循组件即页面的扁平结构，每个 React 函数组件对应一组相关样式类。
- 设计系统与主题：通过 :root 声明全局字体族（Inter + Noto Sans SC）、主文本色 #18201d、背景色 #eef2ef；侧边栏深色主题使用 #17221e，强调色为绿色系（#196f49 / #137648 / #258158），状态色以绿/红/黄三色圆角徽章表达（.decision.allow/block/warning、.status.off、.proxy-node-delay.fast/medium/slow/timeout）。
- 布局策略：基于 CSS Grid 和 Flexbox 的响应式网格，固定最小宽度 min-width:980px，整体采用双栏 shell 布局（grid-template-columns:248px 1fr），卡片统一 border-radius:14px、浅灰边框 #dce3df、柔和阴影，形成一致的面板视觉语言。
- 交互与动效：仅使用 CSS transition（如 .switch.on、.locked:hover、.proxy-node:hover）实现开关、悬停反馈，无第三方动画库；弹窗使用 position:fixed + backdrop-filter:blur(5px) 遮罩层。
- 图标与资源：图标来自 lucide-react，作为 React 组件直接嵌入 JSX，无需额外 SVG 资源管理。
- 构建集成：Vite 默认处理 CSS，index.html 中仅挂载 #root，main.tsx 引入 styles.css 完成全局注入，无独立的 CSS 入口拆分或按需加载机制。

开发者约定：新增 UI 元素应在 App.tsx 中以小函数组件形式实现，并在 src/styles.css 末尾追加对应 class 规则，保持命名与现有风格一致；避免在组件内写行内样式或使用 CSS Modules，以维持单文件样式的可维护性。