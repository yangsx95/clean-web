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
- `apps/android/app/build.gradle.kts`
- `README.md`
- `README.zh-CN.md`
- `apps/desktop/src/App.tsx`
- `website/index.html`
- `website/release.json`

Android 原生原型使用独立 `versionCode`。脚本默认将当前 `versionCode` 加 1；如需指定，传入 `--android-version-code`。

## 版本升级

先预览变更：

```bash
scripts/release/bump-version.sh 0.2.0 --dry-run
```

确认后执行：

```bash
scripts/release/bump-version.sh 0.2.0
```

指定 Android `versionCode`：

```bash
scripts/release/bump-version.sh 0.2.0 --android-version-code 2
```

Android `versionName` 默认规则：

- 如果当前值带有 `-android-prototype` 后缀，新值会保留该后缀，例如 `0.2.0-android-prototype`。
- 如果当前值没有后缀，新值就是主版本号，例如 `0.2.0`。

## 发布前验证

先运行自动检查：

```bash
scripts/release/preflight.sh
```

该脚本按项目当前验证要求执行：

```bash
npm test
npm run build
cd apps/desktop/src-tauri && cargo test
cd apps/desktop/src-tauri && cargo clippy --all-targets -- -D warnings
```

如果本次修改涉及 Android 原生应用，还需额外执行：

```bash
cd apps/android && ./gradlew test
```

如果本次修改涉及 UI 布局，还需启动应用并在相关视口做视觉验证。

## 人工发布检查

发布前逐项确认：

- 版本号已通过脚本同步更新，没有手写遗漏。
- `git diff` 中没有无关改动。
- `package-lock.json` 与 `package.json` 版本一致。
- Tauri `Cargo.toml` 和 `tauri.conf.json` 版本一致。
- Android `versionCode` 单调递增。
- Mihomo 随包资源版本、许可证记录和归属说明准确。
- macOS 发布包完成 Developer ID 签名和 Apple 公证。
- Windows 发布包验证服务安装、升级和卸载恢复。
- Android 发布包验证 `VpnService` 启动、停止和升级路径。
- 真实网络验证覆盖保护开启、拦截、代理、安全搜索、日志、崩溃恢复和卸载恢复。
- Release notes 说明用户可见变化、已知风险和升级注意事项。

## 打标签

自动检查和人工检查通过后，创建发布标签：

```bash
scripts/release/tag-release.sh 0.2.0
```

脚本会拒绝在工作区未清理时打标签。推送标签前再次确认产物和 Release notes 已匹配同一版本。
