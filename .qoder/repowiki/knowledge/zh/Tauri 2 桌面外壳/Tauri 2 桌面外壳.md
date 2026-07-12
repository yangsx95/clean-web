---
kind: external_dependency
name: Tauri 2 桌面外壳
slug: tauri-2
category: external_dependency
category_hints:
    - vendor_identity
scope:
    - '**'
---

### Tauri 2
- 角色：Windows/macOS 桌面外壳，承载 React+TypeScript UI 并通过 `#[tauri::command]` 暴露给前端。
- 集成点：`package.json` 中 `@tauri-apps/api` + `@tauri-apps/cli`，Rust 侧 `Cargo.toml` 依赖 `tauri = "2"`；开发命令 `npm run tauri dev`。
- 稳定用法要点：UI 层只调用受控的 Rust 命令，不直接读写生成的代理配置。