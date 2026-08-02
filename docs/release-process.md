# CleanWeb 发布流程

本文档规范 CleanWeb 每次应用发布前的版本升级、验证和人工检查。发布动作应优先通过 `scripts/release/` 下的脚本执行，人工步骤记录在本文档中；等流程稳定跑过数次后，再把该流程包装为 Codex skill。

## 发布边界

- V1 发布必须遵守 `docs/product-spec.md` 和 `docs/architecture.md` 中的产品与架构边界。
- 应用更新由用户确认安装，不能加入静默强制升级。
- Mihomo 随应用版本发布，不做独立在线替换。
- 发布前必须确认对应 Mihomo 二进制版本、许可证、归属和源代码义务。
- macOS/Windows/Android/iOS 的发布动作不得越过 `docs/project-structure.md` 和 `docs/platforms/` 中的平台边界。

## 版本号来源

发布版本以根目录 `package.json` 的 `version` 为应用主版本号。版本升级脚本会同步更新以下位置：

- `package.json`
- `package-lock.json`
- `apps/desktop/src-tauri/Cargo.toml`
- `apps/desktop/src-tauri/tauri.conf.json`
- `apps/mobile/src-tauri/Cargo.toml`
- `apps/mobile/src-tauri/tauri.conf.json`
- `crates/cleanweb-rules/Cargo.toml`
- `crates/cleanweb-subscriptions/Cargo.toml`
- `crates/cleanweb-proxy-import/Cargo.toml`
- `README.md`
- `README.zh-CN.md`
- `packages/frontend/App.tsx`
- `website/index.html`
- `website/release.json`

## 版本升级

先预览变更：

```bash
scripts/release/bump-version.sh 0.2.0 --dry-run
```

确认后执行：

```bash
scripts/release/bump-version.sh 0.2.0
```

## 发布前验证

先运行自动检查：

```bash
mise run check
```

该任务按项目当前验证要求执行：

```bash
mise run rules-check
mise run test
mise run build
mise run rust-fmt
mise run rust-test
mise run rust-lint
```

如果本次修改涉及 UI 布局，还需启动应用并在相关视口做视觉验证。

## 桌面安装包矩阵

GitHub Actions 的 `Build` workflow 默认保持快速发布路径：

- macOS 默认构建 `cleanweb-macos-arm64-unsigned` 和 `cleanweb-macos-x64-unsigned`，对应 Apple Silicon 和 Intel 两个 DMG。
- Windows 默认构建 x64 和 ARM64，每个 CPU 各产出 NSIS `.exe` 和 MSI `.msi`。

手动触发 workflow 时可以选择更多 CPU 包：

- `macos_packages=arm64`：只构建 Apple Silicon DMG。
- `macos_packages=x64`：只构建 Intel DMG。
- `macos_packages=all`：同时构建 Apple Silicon 和 Intel DMG。
- `windows_packages=arm64`：只构建 Windows ARM64 的 NSIS `.exe` 和 MSI `.msi`。
- `windows_packages=all`：同时构建 Windows x64 和 ARM64，每个 CPU 各产出 NSIS `.exe` 和 MSI `.msi`。

推送 `v*` 标签时，桌面端会自动构建全量矩阵。除移动端外，桌面发布应有 6 个安装文件：Windows x64 `.exe`、Windows x64 `.msi`、Windows ARM64 `.exe`、Windows ARM64 `.msi`、macOS Apple Silicon `.dmg`、macOS Intel `.dmg`。发布页面应把 macOS Apple Silicon 和 Windows x64 放在默认下载位置，其余 CPU 专用包放在“其他版本”或“高级下载”区域。

## 人工发布检查

发布前逐项确认：

- 版本号已通过脚本同步更新，没有手写遗漏。
- `git diff` 中没有无关改动。
- `package-lock.json` 与 `package.json` 版本一致。
- Tauri `Cargo.toml` 和 `tauri.conf.json` 版本一致。
- Mihomo 随包资源版本、许可证记录和归属说明准确。
- macOS 发布包完成 Developer ID 签名和 Apple 公证。
- Windows 发布包验证服务安装、升级和卸载恢复。
- Android/iOS 移动发布包从 `apps/mobile` 构建，并验证对应 VPN 插件启动、停止和升级路径。
- 真实网络验证覆盖保护开启、拦截、代理、安全搜索、日志、崩溃恢复和卸载恢复。
- Release notes 说明用户可见变化、已知风险和升级注意事项。

## 打标签

自动检查和人工检查通过后，创建发布标签：

```bash
scripts/release/tag-release.sh 0.2.0
```

脚本会拒绝在工作区未清理时打标签。推送标签前再次确认产物和 Release notes 已匹配同一版本。
