# CleanWeb 项目结构

CleanWeb 当前是一个同仓库多平台项目：桌面端使用 Tauri + React + Rust，Android 端使用原生 Kotlin + Jetpack Compose + `VpnService` 原型。共享的是产品边界、策略语义、规则资源和后续可抽取的领域模型，不强求共享所有平台 UI 或系统集成代码。

## 顶层目录

```text
clean-web/
  apps/
    desktop/       # 桌面端：macOS / Windows / Linux
    android/       # Android 原生原型，Kotlin + Compose + VpnService
    ios/           # iOS 原生端，未来新增
  crates/          # 跨平台共享 Rust 核心
  resources/       # 跨平台共享规则、安全搜索等资源
  docs/            # 产品、架构、实现状态和结构文档
  website/         # 官网静态页
  assets/          # 通用品牌资源
  .github/         # GitHub Actions 工作流
```

生成目录不属于源码结构：`node_modules/`、`dist/`、`apps/desktop/dist/`、`apps/desktop/src-tauri/target/`、`apps/android/.gradle/`、`apps/android/app/build/`。

## 桌面前端

```text
apps/desktop/
  index.html
  vite.config.ts
  tsconfig.json
  src/
    App.tsx        # 桌面主界面和主要交互
    backend.ts     # Tauri 命令调用封装
    policy.ts      # 前端策略展示和转换辅助
    main.tsx       # React 入口
    styles.css     # 桌面 UI 样式
    *.test.ts(x)   # Vitest 测试
```

前端只通过 `backend.ts` 调用窄范围 Tauri 命令，不直接编辑生成的 Mihomo 配置，也不绕过 Rust 后端的策略边界。

## 桌面 Rust 后端

```text
apps/desktop/src-tauri/
  src/
    lib.rs                       # Tauri 命令注册和应用状态
    main.rs                      # 桌面进程入口
    storage.rs                   # SQLite 设置、规则、订阅、日志存储
    rules.rs                     # re-export cleanweb-rules，兼容桌面现有调用
    builtin_rules.rs             # 内置规则源加载
    subscriptions.rs             # re-export cleanweb-subscriptions，兼容桌面现有调用
    subscription_download.rs     # 订阅下载、代理 payload 加密入库和安全搜索导入
    mihomo.rs                    # Mihomo 配置生成、启动和日志消费
    access_logs.rs               # 访问日志模型、保留和导出
    proxy_crypto.rs              # 代理敏感数据加密
    platform.rs                  # 当前平台适配入口，后续可拆 macos/windows/linux
  resources/
    mihomo/                      # 随应用分发的 Mihomo 可执行资源
  icons/                         # 桌面和移动图标资源
  tauri.conf.json                # Tauri 应用配置
```

Rust 后端是桌面端的策略权威：代理订阅不能修改 DNS、TUN、过滤规则、系统路由或绕过策略。过滤规则必须先于代理路由。

## Android 原型

```text
apps/android/
  settings.gradle.kts            # Android Gradle 项目入口
  build.gradle.kts               # Android/Kotlin/Compose 插件版本
  gradle.properties              # AndroidX 和 Gradle 配置
  README.md                      # Android 原型范围和下一步
  app/
    build.gradle.kts             # Android App 模块配置
    src/main/
      AndroidManifest.xml        # Activity、VpnService 和权限声明
      java/app/cleanweb/android/
        MainActivity.kt          # Compose App 入口和 VPN 权限流
        ui/                      # Android UI
        vpn/                     # Android VpnService 生命周期占位
      res/                       # Android 字符串、主题和图标
```

Android 当前只完成工程骨架、VPN 权限流和前台服务占位。真实过滤、Mihomo 数据路径、Keystore、日志和规则复用还未实现。

## 文档

```text
docs/
  product-spec.md              # V1 产品边界和验收标准
  architecture.md              # 平台架构、网络生命周期和模块边界
  implementation-status.md     # 当前能力审计
  project-structure.md         # 本文档
  platforms/
    desktop.md                 # 桌面端总体边界
    android.md                 # Android 平台边界
    ios.md                     # iOS 规划边界
    linux.md                   # Linux 作为桌面平台的差异说明
```

改变行为前先读 `product-spec.md` 和 `architecture.md`。新增平台能力时同步更新 `implementation-status.md`。

## 官网

```text
website/
  index.html
  styles.css
  script.js
  assets/
```

官网是独立静态页，由 GitHub Pages 工作流发布，不参与桌面或 Android App 构建。

## 共享资源

```text
resources/
  rules/                         # 内置 CleanWeb 规则补充包
  safe-search/                   # 安全搜索映射清单
```

这些资源是跨平台语义资源。桌面端当前通过 `include_str!` 编译期嵌入；移动端接入规则和安全搜索能力时应从这里复用同一份资源。

## 共享模块

当前已抽取：

```text
crates/
  cleanweb-rules/                # 共享规则标准化、验证、匹配和优先级
  cleanweb-subscriptions/        # 规则订阅文本解析和导入报告
  cleanweb-proxy-import/         # 代理订阅 URI/YAML 清洗为受控 Clash payload
```

后续当 Android 的 VPN 数据路径验证通过后，再考虑新增：

```text
crates/
  cleanweb-core/                 # 未来：共享设置、分类、动作和日志字段
  cleanweb-policy/               # 共享策略合并和动作判定
  cleanweb-mihomo-config/        # 共享 Mihomo 配置模型和生成
  cleanweb-ffi/                  # Android/iOS 绑定层，确认需要后再建
```

抽共享模块的条件是 Android 和桌面确实需要同一套实现，并且 FFI 或 Kotlin/Rust 绑定成本低于双端维护成本。
