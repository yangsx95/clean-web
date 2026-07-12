---
kind: dependency_management
name: 双栈依赖管理（npm + Cargo）
category: dependency_management
scope:
    - '**'
source_files:
    - package.json
    - package-lock.json
    - src-tauri/Cargo.toml
    - src-tauri/Cargo.lock
---

本项目采用前后端分离的 Tauri 2 架构，因此存在两套独立的依赖管理系统：前端使用 npm（package.json + package-lock.json），后端 Rust 使用 Cargo（Cargo.toml + Cargo.lock）。两者均通过锁定文件保证构建可重现，且均未启用 vendor 或私有仓库。

- 前端依赖（package.json）
  - 运行时依赖：react、react-dom、@tauri-apps/api、lucide-react；开发依赖：vite、typescript、vitest、@testing-library/*、@tauri-apps/cli。
  - 版本策略以 ^ 主/次版本范围为主，仅测试工具使用精确版本（如 @testing-library/react 16.3.2、jsdom 29.1.1）。
  - 锁定文件为 package-lock.json（lockfileVersion 3），提交至版本库，确保 CI 与本地一致。
  - 无 .npmrc、无私有 registry、无 pnpm/yarn 锁文件，默认走 npm 官方源。

- 后端依赖（src-tauri/Cargo.toml）
  - 核心 crate：tauri v2、rusqlite（bundled）、reqwest（rustls-tls）、serde/serde_json/serde_yaml、regex、aes-gcm、argon2、keyring、uuid、thiserror 等。
  - 通过 features 控制可选能力（如 rusqlite 的 bundled、rand_core 的 getrandom、ipnet 的 serde）。
  - 锁定文件 Cargo.lock 提交至版本库，所有包来源均为 crates.io（registry+https://github.com/rust-lang/crates.io-index），未配置 .cargo/config.toml 或私有源。

- 约定与约束
  - 新增依赖需同时更新对应 lock 文件并纳入版本控制。
  - 前端优先使用 ^ 范围保持小版本自动升级，关键测试依赖用固定版本避免测试环境漂移。
  - 后端依赖按功能分组声明在 [dependencies] / [build-dependencies] / [dev-dependencies]，并通过 features 裁剪体积（如 reqwest 关闭 default-features）。
  - 二进制资源（mihomo 内核压缩包、图标、schema）放在 src-tauri/resources 与 icons 目录，不属于包管理器范畴，由 build.rs 与 tauri.conf.json 引用。