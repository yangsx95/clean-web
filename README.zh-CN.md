# CleanWeb

[English](README.md) | 简体中文

CleanWeb 是一个本地优先的桌面网络净化工具，用于内容过滤、安全搜索、代理订阅导入、路由策略和访问日志。项目基于 Tauri、React、TypeScript 和 Rust 构建，并使用 Mihomo 作为受控的 TUN、DNS 和代理执行内核。

CleanWeb 不销售、不提供代理节点。用户导入自己的代理订阅，CleanWeb 负责在本地策略模型下统一管理过滤规则、DNS、TUN、路由和日志。

> 当前状态：`0.1.0` 测试版。适合开发调试和真实网络场景验证。macOS 签名与公证、Windows 服务加固、完整发布许可证声明和更多设备验证仍在进行中。

## 功能

- 本地内容过滤，支持内置规则、自定义黑白名单和规则订阅。
- 通过受控 DNS 和 hosts 映射为支持的搜索服务强制安全搜索。
- 支持 Clash/Mihomo 风格订阅、单节点链接和二维码图片导入代理。
- 代理订阅清洗：只保留代理节点和代理组，丢弃订阅里的 DNS、TUN、脚本、路由规则、本地端口和控制器配置。
- 支持用户自定义直连或代理路由规则。
- 锁定模式隐藏敏感配置，只展示运行状态和统计数字。
- 本地访问日志，支持保留期、筛选、清空和 CSV 导出。
- macOS 和 Windows 桌面构建工作流。
- 官网静态页面位于 `website/`，可通过 GitHub Pages 部署。

## 产品边界

CleanWeb V1 可观察域名、DNS 查询、目标 IP、IPv4/IPv6 CIDR 和 Mihomo 网络事件。它不解密 HTTPS，不检查网页正文、图片、视频、AI 对话或完整 HTTPS URL 路径。

过滤决策必须先于代理路由执行。代理订阅只是输入数据，不能成为策略权威。

修改行为前请先阅读：

- [产品规格](docs/product-spec.md)
- [架构说明](docs/architecture.md)
- [当前实现状态](docs/implementation-status.md)

## 技术栈

- 桌面壳：Tauri 2
- 前端：React 19、TypeScript、Vite
- 后端：Rust
- 网络内核：Mihomo，以独立可执行资源分发
- 存储：由 Rust 后端管理 SQLite
- 测试：Vitest 和 Rust tests

## 环境要求

- Node.js 22+
- npm
- Rust stable toolchain
- 当前平台所需的 Tauri 2 系统依赖
- macOS 13+，当前主要开发目标
- Windows 10 22H2 / Windows 11，用于 Windows 验证

## 本地开发

安装依赖：

```bash
npm install
```

启动前端开发服务：

```bash
npm run dev
```

启动 Tauri 桌面应用：

```bash
npm run tauri dev
```

运行检查：

```bash
npm test
npm run build
cd src-tauri && cargo test
cd src-tauri && cargo clippy --all-targets -- -D warnings
```

## 构建

本地构建桌面应用：

```bash
npm run tauri -- build
```

构建 macOS Universal DMG：

```bash
npm run tauri -- build --target universal-apple-darwin --bundles dmg
```

在 Windows 上构建 NSIS 安装包：

```bash
npm run tauri -- build --bundles nsis
```

[.github/workflows/desktop-build.yml](.github/workflows/desktop-build.yml) 会构建未签名的 Windows 和 macOS 产物。推送 `v*` tag 时会将产物发布到 GitHub Releases。

## 官网

产品官网位于 [website](website)。

本地预览：

```bash
cd website
python3 -m http.server 1432 --bind 127.0.0.1
```

GitHub Pages 部署配置位于 [.github/workflows/pages.yml](.github/workflows/pages.yml)。在仓库设置中将 Pages 来源设置为 GitHub Actions 即可。

## 发布说明

当前构建产物未签名。正式公开分发前需要完成：

- macOS Developer ID 签名和公证。
- Windows 签名和 Windows Service 加固。
- TUN、DNS、代理路由、安全搜索、访问日志、崩溃恢复和卸载恢复的真实网络验证。
- Mihomo 的第三方声明和对应源码义务。
- 内置规则源和官方规则源的许可证与再分发审查。

## 许可证

项目许可证尚未添加。

Mihomo 以独立 GPLv3 可执行资源分发。随 CleanWeb 发布 Mihomo 时，需要提供准确版本归属、许可证声明和对应源码义务。规则源在作为 CleanWeb 官方资源发布前，也需要明确许可证和再分发权限。
