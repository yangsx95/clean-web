# CleanWeb 当前实现审计

审计基线：单 Mihomo/Clash 实现。状态只依据代码和已有自动化测试，不把界面展示或配置文本等同于真实系统能力。

状态含义：

- **已完成**：主要代码路径存在，并有相应测试或本机真实流量证据。
- **部分完成**：已有可运行路径，但缺少产品要求的一部分、可靠性闭环或跨平台验证。
- **未完成**：没有满足需求的实现。

## 当前能力

| 能力 | 状态 | 当前证据与缺口 |
| --- | --- | --- |
| Tauri 管理界面与锁定状态 | 已完成 | React UI 已区分锁定/解锁，敏感命令要求管理会话。 |
| 管理密码 | 部分完成 | Argon2 密码哈希和会话过期已实现；缺少输错退避和系统管理员授权重置。 |
| 单 Mihomo TUN 启停 | 部分完成 | CleanWeb 生成锁定的 Mihomo 配置并启动唯一 TUN；macOS/Windows 的特权安装、升级、异常恢复和卸载仍需真实设备验收。 |
| DNS 接管与安全搜索 | 部分完成 | Mihomo 配置启用 `dns.respect-rules` 和 TUN `dns-hijack` 负责 DNS 接管；SafeSearch 改由 Chrome/Edge 托管浏览器策略处理，DNS hosts 映射方案已移除。仍需真实设备验证浏览器策略写入、浏览器重启后的搜索安全模式，以及非受支持浏览器的产品提示。 |
| 内容过滤优先于代理路由 | 已完成 | 过滤规则排在内置 `DIRECT` 路由前，覆盖 `baidu.com` 这类国内直连域名被家长规则拦截的回归场景。 |
| 跨平台规则核心 | 部分完成 | 规则标准化、匹配、优先级和基础测试已抽到 `crates/cleanweb-rules`；规则订阅文本解析已抽到 `crates/cleanweb-subscriptions`；代理订阅 URI/YAML 清洗已抽到 `crates/cleanweb-proxy-import`；桌面端通过兼容层复用。策略合并和 Mihomo 配置生成尚未抽取。 |
| Tauri mobile 共享界面 | 部分完成 | `apps/mobile/` 是唯一移动端 app 壳，已新增 Tauri mobile/Vite 骨架，并挂载 `packages/frontend` 的共享 React 管理界面。Android 和 iOS Tauri shell 已生成。尚未接入 Android `VpnService` 或 iOS Network Extension 插件。 |
| Clash/Mihomo 代理订阅清洗 | 已完成 | 只保留节点和允许的代理组；订阅里的 DNS、TUN、规则、脚本、本地端口和控制器不会进入受控配置。纯解析和清洗逻辑已在 `cleanweb-proxy-import` 中覆盖测试，桌面端只负责下载、加密和存储。 |
| 规则订阅导入 | 已完成 | Clash、Adblock、hosts、域名和 IP/CIDR 均有解析路径和测试；安全搜索不再作为规则订阅格式暴露给用户。 |
| 内置规则包 | 部分完成 | 共享规则发布素材已移动到根 `resources/`；有内置规则源、默认启用、不可删除和启动恢复逻辑；缺少许可证、归属、版本、校验和、签名包以及商业再分发审计字段。 |
| 访问日志 | 部分完成 | 日志模型、保留期、清空和 CSV 导出存在；拦截事件已从 Mihomo 日志流写入 SQLite 并通过 Tauri event 驱动前端刷新；仍需真实设备验证 DNS、连接和规则命中事件覆盖率。 |
| 代理凭据加密 | 部分完成 | 已有 payload 加密和迁移测试；Windows DPAPI、macOS Keychain 的发布级路径仍需验收。 |
| 发布许可证交付 | 未完成 | Mihomo GPLv3 边界已在架构中声明，但安装包 notices、对应源码和第三方规则许可证流程尚未完成。 |

## 建议实施顺序

1. 用真实 Mihomo TUN 验收 DNS 接管、fake-ip 排除和代理模式下的上游 DNS 解析。
2. 验证 Chrome/Edge 浏览器策略对 Google SafeSearch、YouTube 受限模式和浏览器 DoH 关闭的真实生效矩阵。
3. 用真实流量验证 Mihomo 日志流采集覆盖率，补齐 DNS、连接和规则命中事件的分类归因。
4. 在 `apps/mobile` 中实现 Android `VpnService`、Mihomo 和 `tun2socks` Tauri 插件，并完成 iOS Packet Tunnel Provider 插件可行性验证。
5. 完成特权组件安装、崩溃恢复、主动关闭、升级和卸载恢复闭环。
6. 建立经许可证审核、签名、可回退的官方基础规则包和 canonical rule 来源模型。
