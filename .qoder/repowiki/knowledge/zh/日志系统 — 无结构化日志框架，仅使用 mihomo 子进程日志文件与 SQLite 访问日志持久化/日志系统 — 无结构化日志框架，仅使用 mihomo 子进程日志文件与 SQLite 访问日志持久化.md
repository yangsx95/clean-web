---
kind: logging_system
name: 日志系统 — 无结构化日志框架，仅使用 mihomo 子进程日志文件与 SQLite 访问日志持久化
category: logging_system
scope:
    - '**'
source_files:
    - src-tauri/Cargo.toml
    - src-tauri/src/lib.rs
    - src-tauri/src/main.rs
    - src-tauri/src/access_logs.rs
    - src-tauri/src/mihomo.rs
---

本仓库未引入任何 Rust 日志框架（Cargo.toml 中无 tracing、slog、env_logger、log、fern、simplelog 等依赖），也未在 main.rs / lib.rs 中进行日志初始化。Rust 后端没有统一的程序运行期日志输出机制。

当前“日志”能力集中在两个独立方向：
1) 用户访问日志（access_logs）：通过 access_logs.rs 将 mihomo 内核的访问记录同步到 SQLite 数据库 cleanweb.db 中的 access_logs 表，并提供 list_access_logs、clear_access_logs、export_access_logs_csv 等 Tauri invoke 接口供前端查看/导出；同时支持按 log_retention 配置清理旧记录。
2) mihomo 子进程日志：mihomo.rs 启动 mihomo 内核后将其标准输出重定向到 runtime/mihomo.log 文件，作为内核运行日志的唯一落盘位置。

前端（src/App.tsx、src/backend.ts）仅通过 console.error 打印调用异常，未封装统一的前端 logger。

结论：该仓库不存在跨模块的统一 logging_system，仅有面向用户的访问日志持久化与 mihomo 子进程的独立日志文件。