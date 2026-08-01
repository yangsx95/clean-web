# CleanWeb

[English](README.md) | 简体中文

CleanWeb 是一个本地优先的桌面网络净化工具，用于内容过滤、安全搜索、代理订阅管理、路由策略和本地访问日志。

- 官网：[https://yangsx95.github.io/clean-web/](https://yangsx95.github.io/clean-web/)
- 下载：[GitHub Releases](https://github.com/yangsx95/clean-web/releases/latest)
- 当前版本：`0.1.0` 测试版
- 平台：macOS 13+ 优先，Windows 10 22H2 / Windows 11 验证中，Android/iOS 使用 [apps/mobile](apps/mobile) 的 Tauri mobile 壳

> 测试版说明：当前构建适合功能测试和真实网络场景验证。macOS 签名与公证、Windows 服务加固、完整许可证声明和更多设备验证仍在进行中。

## 它能做什么

CleanWeb 帮助家庭用户和个人自律用户在一个桌面应用里管理设备网络访问：

- 拦截不希望访问的域名、IP 和规则订阅条目。
- 为支持的搜索服务强制开启安全搜索。
- 导入你自己的代理订阅和代理节点。
- 决定已允许的流量走直连还是代理。
- 保存本地访问日志，支持统计、筛选、导出和保留期。
- 用管理密码锁定敏感设置。

CleanWeb **不销售代理节点、不托管代理服务，也不解密 HTTPS 流量**。

## 工作方式

CleanWeb 使用本地策略引擎，并将 Mihomo 作为受控的 TUN、DNS 和代理执行内核。过滤规则先于代理路由执行，因此代理订阅不能绕过 CleanWeb 的内容策略。

导入代理订阅时，CleanWeb 只保留代理节点和代理组。订阅里的 DNS、TUN、脚本、路由规则、本地端口和控制器配置都会被丢弃。

## 产品边界

CleanWeb V1 可观察域名、DNS 查询、目标 IP、IPv4/IPv6 CIDR 和 Mihomo 网络事件。它不检查网页正文、图片、视频、AI 对话或完整 HTTPS URL 路径。

详细产品和架构边界见：

- [产品规格](docs/product-spec.md)
- [架构说明](docs/architecture.md)
- [当前实现状态](docs/implementation-status.md)
- [项目结构](docs/project-structure.md)

## 开发者

CleanWeb 使用：

- Tauri 2
- React 19、TypeScript、Vite
- Rust
- Android/iOS 使用 Tauri mobile 壳
- Mihomo 独立可执行资源
- Rust 后端管理 SQLite
- Vitest 和 Rust tests

安装依赖：

```bash
mise trust
mise install
mise run install
```

启动桌面应用：

```bash
mise run dev
```

运行检查：

```bash
mise run check
```

## 构建

本地构建：

```bash
mise run desktop-build
```

构建 macOS Universal DMG：

```bash
mise run rust-targets-macos
mise run desktop-build-macos
```

在 Windows 上构建 NSIS 安装包：

```bash
mise run desktop-build-windows
```

GitHub Actions 使用同一套 mise tasks 构建未签名的 Windows、macOS、Android 和 iOS 模拟器产物。推送 `v*` tag 时会将产物发布到 GitHub Releases。

## 官网

产品官网源码位于 [website](website)。GitHub Pages 部署配置位于 [.github/workflows/pages.yml](.github/workflows/pages.yml)。在仓库设置中将 Pages 来源设置为 GitHub Actions 即可。

## 许可证

项目许可证尚未添加。

Mihomo 以独立 GPLv3 可执行资源分发。随 CleanWeb 发布 Mihomo 时，需要提供准确版本归属、许可证声明和对应源码义务。规则源在作为 CleanWeb 官方资源发布前，也需要明确许可证和再分发权限。
