---
kind: external_dependency
name: Mihomo 内核（外部 GPLv3 代理核心）
slug: mihomo
category: external_dependency
category_hints:
    - vendor_identity
    - framework_behavior
scope:
    - '**'
---

### Mihomo 内核
- 角色：CleanWeb 的流量捕获与代理转发核心，以独立二进制分发，通过配置文件和外部 REST API 控制。
- 稳定用法要点：
  - 配置由 CleanWeb 生成，仅注入 `mixed-port`、`tun`、`dns`、`sniffer`、`proxy-groups`、`rules` 等字段，不直接编辑订阅中的 DNS/路由/脚本/TUN 设置。
  - 控制器鉴权使用随机 secret，通过 HTTP Bearer Token 传递；重启后需重新读取 PID 文件恢复状态。
  - 规则顺序固定：局域网/私有地址 → Apple/Microsoft 系统服务直连 → 导入的规则 → `GEOIP,CN,DIRECT,no-resolve`（开启代理时）→ 末尾 `MATCH` 指向 `CleanWeb` 或 `DIRECT`。
- 许可证：架构文档明确其为 GPLv3 程序，发布时需附带对应源码与通知。