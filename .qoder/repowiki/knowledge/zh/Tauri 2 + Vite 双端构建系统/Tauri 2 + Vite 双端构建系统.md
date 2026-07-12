---
kind: build_system
name: Tauri 2 + Vite 双端构建系统
category: build_system
scope:
    - '**'
source_files:
    - package.json
    - src-tauri/Cargo.toml
    - src-tauri/tauri.conf.json
    - vite.config.ts
    - src-tauri/build.rs
    - tsconfig.json
---

本项目采用 Tauri 2 作为桌面应用宿主，结合 Vite 构建 React 前端、Cargo 编译 Rust 后端的双端构建体系。整体流程由 tauri.conf.json 统一编排，通过 npm scripts 串联前后端构建步骤。

构建工具链与脚本：
- 前端：Vite 6 + TypeScript 5.7 + React 19，开发服务器监听 1420 端口（vite.config.ts），测试使用 Vitest 2。
- 后端：Rust/Cargo，crate 同时输出 staticlib/cdylib/rlib 三种类型以适配 Tauri 插件机制。
- 顶层 npm scripts：dev 启动 Vite HMR；build 先执行 tsc 再 vite build；tauri 直接转发给 @tauri-apps/cli。

Tauri 构建编排：
- src-tauri/tauri.conf.json 中 beforeDevCommand: "npm run dev"、devUrl: http://127.0.0.1:1420 使 Tauri 在开发模式下直接加载 Vite 热更新的前端；beforeBuildCommand: "npm run build" 与 frontendDist: "../dist" 指定打包时前端产物位置。
- src-tauri/build.rs 仅调用 tauri_build::build()，由 tauri-build 在编译期生成平台 schema 与能力清单。
- 打包目标配置为 ["app", "dmg"]，图标集覆盖 Windows/macOS/iOS/Android 多平台，资源目录包含预编译的 mihomo 内核与 safe-search 默认规则。

版本与依赖管理：
- 版本号在 package.json、src-tauri/Cargo.toml、src-tauri/tauri.conf.json 三处同步维护为 0.1.0，未引入自动化版本注入。
- 前端依赖锁定于 package-lock.json，Rust 依赖锁定于 src-tauri/Cargo.lock。
- mihomo 内核 v1.19.28 以 gzip 压缩文件形式内嵌到 src-tauri/resources/mihomo/，按平台分发。

跨平台与 CI：
- 仓库未发现 Makefile、Dockerfile、GitHub Actions 等 CI/CD 配置文件，也未见自定义 cross-compile 脚本。
- 当前发布说明（HANDOFF.md）提及 ad-hoc 签名用于本地测试，未见正式签名或自动发布流水线。

开发者约定：
- 新增前端功能后需确保 tsconfig.json 的 strict、isolatedModules 等严格模式选项保持开启。
- 修改 Tauri 命令或能力时需重新运行 tauri dev 以触发 tauri-build 重新生成 schema。
- 若调整打包目标或资源，需同步更新 tauri.conf.json 的 bundle.targets 与 resources 字段。