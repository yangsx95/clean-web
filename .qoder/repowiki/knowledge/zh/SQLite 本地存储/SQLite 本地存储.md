---
kind: external_dependency
name: SQLite 本地存储
slug: sqlite-rusqlite
category: external_dependency
category_hints:
    - vendor_identity
scope:
    - '**'
---

### SQLite (rusqlite)
- 角色：持久化策略、规则、订阅、代理元数据与访问日志；通过 `rusqlite` 的 `bundled` 特性在运行时内嵌数据库引擎。