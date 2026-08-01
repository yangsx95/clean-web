# CleanWeb 项目结构

CleanWeb 是同仓库多平台项目。长期主线是共用 Tauri + React 管理界面和 Rust 核心策略，平台系统接管能力通过窄插件或服务边界实现。

当前桌面端使用 Tauri + React + Rust。移动端新增 `apps/mobile` 作为 Tauri mobile 入口，并复用桌面 React 管理界面。现有 `apps/android` Kotlin + Compose 工程保留为 Android VPN 数据通道原型和未来 Tauri Android VPN 插件的迁移来源。

## 顶层目录

```text
clean-web/
  apps/
    desktop/       # 桌面端：macOS / Windows / Linux
    mobile/        # 移动端主线：Tauri mobile + 共享 React 管理界面
    android/       # Android VPN 原型，后续收敛为 Tauri Android 插件
    ios/           # iOS Network Extension 规划占位
  crates/          # 跨平台共享 Rust 核心
  resources/       # 跨平台共享规则、安全搜索等资源
  platforms/       # 平台原生系统能力边界说明和后续插件落点
  docs/            # 产品、架构、实现状态和结构文档
  website/         # 官网静态页
  assets/          # 通用品牌资源
  .github/         # GitHub Actions 工作流
```

生成目录不属于源码结构：`node_modules/`、`dist/`、`apps/desktop/dist/`、`apps/mobile/dist/`、`apps/*/src-tauri/target/`、`apps/android/.gradle/`、`apps/android/app/build/`。

## 桌面端

```text
apps/desktop/
  index.html
  vite.config.ts
  tsconfig.json
  src/
    App.tsx        # 共享管理界面和主要交互
    backend.ts     # Tauri 命令调用封装
    policy.ts      # 前端策略展示和转换辅助
    main.tsx       # 桌面 React 入口
    styles.css     # 共享 UI 样式
    *.test.ts(x)   # Vitest 测试
  src-tauri/
    src/           # 桌面 Rust/Tauri 后端
    resources/     # 桌面 Mihomo 可执行资源
    icons/         # 桌面和移动图标资源
```

桌面端覆盖 macOS、Windows 和未来 Linux。Linux 属于 `apps/desktop`，不是单独顶层 app；差异应隔离在 Rust platform adapter 和特权服务边界里。

## 移动端主线

```text
apps/mobile/
  index.html
  vite.config.ts
  tsconfig.json
  src/
    main.tsx                    # 复用 apps/desktop/src/App.tsx 和 styles.css
  src-tauri/
    Cargo.toml                  # Tauri mobile shell
    tauri.conf.json
    src/
      lib.rs
      main.rs
```

`apps/mobile` 是 Android 和 iOS 的产品 UI 主线。新的管理功能优先进入共享 React/Rust 层，避免桌面、Android、iOS 三套 UI 分叉。移动端不能直接拥有系统 VPN 接管逻辑，应通过平台插件调用 Android `VpnService` 或 iOS Packet Tunnel Provider。

## Android VPN 原型

```text
apps/android/
  settings.gradle.kts
  build.gradle.kts
  gradle.properties
  README.md
  app/
    build.gradle.kts
    src/main/
      AndroidManifest.xml
      java/app/cleanweb/android/
        MainActivity.kt          # Compose 过渡入口
        ui/                      # 过渡 UI
        vpn/                     # Android VpnService、Mihomo、tun2socks 原型
      res/
```

Android 当前用于验证平台 VPN 数据通道：VPN 权限、前台服务、Mihomo、`tun2socks`、基础配置生成和真机调试。它不再作为完整 Android 产品 UI 的扩展方向；验证稳定后，应把 `VpnService`、Mihomo 生命周期、前台服务和 Android 权限流收敛到 Tauri Android 插件，由 `apps/mobile` 调用。

## 平台原生边界

```text
platforms/
  README.md
  android-vpn/                  # Android VpnService 插件边界
  ios-network-extension/         # iOS Packet Tunnel Provider 边界
  desktop-privileged/            # 桌面特权服务边界
```

平台目录不承载共享业务逻辑。它只描述和承接无法跨平台复用的系统能力：Android `VpnService`、iOS Network Extension、桌面 TUN/DNS/路由特权服务。规则、订阅、策略、日志字段和 Mihomo 配置模型应继续抽入 `crates/`。

## 文档

```text
docs/
  product-spec.md              # V1 产品边界和验收标准
  architecture.md              # 平台架构、网络生命周期和模块边界
  implementation-status.md     # 当前能力审计
  project-structure.md         # 本文档
  platforms/
    desktop.md                 # 桌面端总体边界
    mobile.md                  # 移动端共享 UI 与原生插件边界
    android.md                 # Android 平台边界
    ios.md                     # iOS 规划边界
    linux.md                   # Linux 作为桌面平台的差异说明
```

改变行为前先读 `product-spec.md` 和 `architecture.md`。新增平台能力时同步更新 `implementation-status.md`。

## 共享资源

```text
resources/
  rule-sources/                  # 官方和推荐规则源元数据发布素材
  rules/                         # CleanWeb 规则补充包发布素材
  safe-search/                   # 安全搜索映射清单
```

这些资源是跨平台语义资源和发布素材。桌面端不打包、不编译 `resources/rule-sources/` 和 `resources/rules/`；官方规则源和规则正文应通过在线同步写入本地数据库。移动端接入规则能力时也应遵守同一供应链边界。

## 共享模块

当前已抽取：

```text
crates/
  cleanweb-rules/                # 共享规则标准化、验证、匹配和优先级
  cleanweb-subscriptions/        # 规则订阅文本解析和导入报告
  cleanweb-proxy-import/         # 代理订阅 URI/YAML 清洗为受控 Clash payload
```

后续建议新增：

```text
crates/
  cleanweb-core/                 # 共享设置、分类、动作和日志字段
  cleanweb-policy/               # 共享策略合并和动作判定
  cleanweb-mihomo-config/        # 共享 Mihomo 配置模型和生成
  cleanweb-ffi/                  # Android/iOS 绑定层，确认需要后再建
```

抽共享模块的条件是桌面和移动端确实需要同一套实现，并且 Rust API、Tauri command 或 FFI 绑定成本低于双端维护成本。移动端产品 UI 已经选择复用 React，因此后续优先抽 Rust 核心和 Tauri 插件，而不是继续扩 Kotlin Compose 管理界面。
