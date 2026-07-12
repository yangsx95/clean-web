---
kind: error_handling
name: Rust Tauri 命令层的 String 错误传播模式
category: error_handling
scope:
    - '**'
source_files:
    - src-tauri/src/lib.rs
    - src-tauri/src/storage.rs
    - src-tauri/src/mihomo.rs
    - src-tauri/src/subscription_download.rs
    - src-tauri/src/access_logs.rs
---

## 1. 采用的错误处理体系

- 统一返回类型：所有 #[tauri::command] 暴露给前端的函数均使用 Result<T, String>，错误以人类可读的中文字符串形式向上层传递。
- 本地化 error 适配器：每个模块在文件末尾定义同名 fn error(value: impl std::fmt::Display) -> String { value.to_string() }，配合 .map_err(error)? 把底层 rusqlite::Result、reqwest、serde_yaml 等错误统一转换为 String。
- 会话鉴权集中校验：通过 AppState::require_session(&token) 在每条写操作入口检查管理会话是否有效，失败时返回固定中文提示“管理会话已过期，请重新解锁”。
- 业务错误显式构造：对输入校验（密码长度、订阅 URL 协议、规则动作/匹配类型）、资源状态（数据库不可用、内核状态不可用）以及外部依赖异常（网络冲突、Mihomo 启动失败），均使用 Err("...".into()) 或 format!(...) 生成明确语义的错误信息。
- 持久化错误记录：订阅刷新流程中，下载失败、大小超限、解析错误等会调用 record_error(state, id, message) 将错误写入 subscriptions.last_error 字段，供前端轮询展示。

## 2. 关键文件与位置

- src-tauri/src/lib.rs：Tauri 应用初始化；.run(...).expect("failed to run CleanWeb") 作为唯一 panic 点
- src-tauri/src/storage.rs：AppState 生命周期、会话管理、设置/订阅/规则 CRUD；定义 error 适配器和 require_session
- src-tauri/src/mihomo.rs：Mihomo 内核进程管理、配置生成、控制器 HTTP 交互；大量 .map_err(error)? 与业务 Err(format!(...))
- src-tauri/src/subscription_download.rs：订阅拉取、格式识别、YAML/URI 列表解析；record_error 持久化错误
- src-tauri/src/access_logs.rs：访问日志同步与导出；内部后台线程调用 sync_access_logs_inner 并忽略错误（let _ = ...）

## 3. 架构与约定

- 无自定义 Error 枚举：项目未引入 thiserror/anyhow，也未定义统一的 AppError 类型，所有错误均以 String 表达，便于直接透传给前端 UI。
- Tauri invoke_handler 白名单：仅通过 tauri::generate_handler! 注册的方法才会被前端调用，天然形成“受控入口”，所有错误路径都经过这些方法。
- 后台任务静默失败：lib.rs 中每 750ms 触发的 access_logs::sync_access_logs_inner 使用 let _ = tauri::async_runtime::block_on(...) 丢弃错误，避免后台同步阻塞影响主进程。
- panic 仅用于不可恢复场景：目前仅在 run().expect("failed to run CleanWeb") 一处使用 expect，其余地方全部走 Result 返回，没有 panic!/unwrap() 滥用。

## 4. 开发者应遵循的规则

1. 对外暴露的函数一律返回 Result<T, String>，不要使用 panic! 或裸 unwrap()。
2. 在本模块内定义 fn error(...) -> String 适配器，并用 .map_err(error)? 包装第三方库错误，保持错误信息为中文可读字符串。
3. 涉及敏感操作的命令必须先调用 state.require_session(token)，并在失败时返回明确的中文提示。
4. 可持久化的错误（如订阅刷新失败）应同时写入 last_error 字段，并通过 record_error 辅助函数统一处理。
5. 后台定时任务中的错误可以安全丢弃（如访问日志同步），但需加注释说明原因，避免误吞用户可见的错误。
6. 业务校验错误使用具名中文消息（如“管理密码至少需要8个字符”、“订阅仅支持 HTTP 或 HTTPS 地址”），以便前端直接展示给用户。