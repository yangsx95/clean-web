---
kind: configuration_system
name: CleanWeb 配置系统：基于 SQLite 的设置持久化与运行时配置生成
category: configuration_system
scope:
    - '**'
source_files:
    - src-tauri/src/storage.rs
    - src-tauri/src/mihomo.rs
    - src-tauri/src/lib.rs
    - src-tauri/tauri.conf.json
    - src-tauri/resources/safe-search/defaults.yaml
---

## 1. 系统概览
CleanWeb 的配置系统由两层构成：
- 应用设置层：以键值对形式持久化到 SQLite（cleanweb.db），通过 Tauri command 暴露 get_settings / update_setting 供前端读写，并提供白名单校验。
- 内核配置层：在运行时根据当前设置、订阅数据和安全搜索映射动态生成 Mihomo 的 config.yaml，写入用户数据目录并通过外部控制器热重载。
此外，Tauri 自身构建/打包配置位于 src-tauri/tauri.conf.json，内置资源（mihomo 二进制、安全搜索默认映射）通过 resources 字段注入。

## 2. 关键文件与位置
- src-tauri/src/storage.rs：SQLite schema、默认设置初始化、设置读取/更新、密码与会话管理。
- src-tauri/src/mihomo.rs：build_config() 将设置 + 订阅数据渲染为 Mihomo YAML；启动/停止/热重载内核。
- src-tauri/src/lib.rs：Tauri 入口，注册所有 #[tauri::command]，创建 AppState 并挂载后台任务。
- src-tauri/tauri.conf.json：Tauri 2 应用元数据、窗口尺寸、bundle 资源清单。
- src-tauri/resources/safe-search/defaults.yaml：搜索引擎安全搜索默认映射表。
- src-tauri/Cargo.toml：依赖声明（rusqlite、serde_yaml、keyring 等）。

## 3. 架构与设计约定
### 3.1 应用设置（settings）
- 存储介质：SQLite 单文件 cleanweb.db，位于 app_data_dir（跨平台由 Tauri path API 提供）。
- Schema 初始化：initialize_schema() 在首次打开时执行，包含 settings、subscriptions、parent_rules、proxy_payloads、access_logs、safe_search_mappings、app_secrets 等表。
- 默认值策略：INSERT OR IGNORE 插入一组固定 key-value 对（如 protection_enabled=false、log_retention=30d、各类 category.*=true），保证新安装即有可预期行为。
- 访问接口：
  - get_settings：返回聚合后的 Settings 结构体（布尔开关 + category map + log_retention）。
  - update_setting(key, value)：经 allowed_setting() 白名单校验后落库，并在开启代理前检查是否存在可用节点。
- 白名单约束：仅允许 protection_enabled、proxy_enabled、automatic_node_selection、access_logging_enabled、safe_search_enabled、log_retention（枚举值）以及 category.<name> 前缀的布尔项，其余一律拒绝。
- 安全相关：管理密码哈希存于 app_secrets.password_hash，通过 Argon2 验证；解锁后生成 UUID session token，有效期 15 分钟，受 require_session() 保护。

### 3.2 内核配置（Mihomo config.yaml）
- 生成时机：每次启动/停止/热重载保护时调用 build_config(&state, secret, tun_enabled)。
- 数据来源：从 settings 表读开关、从 proxy_selections 读分组选择、从 proxy_payloads 解密拉取 Clash 格式订阅、从 safe_search_mappings 读映射。
- 输出路径：data_dir/mihomo/config.yaml，通过原子写 + 外部控制器 /configs 端点热重载。
- 安全过滤：secret 不会写入最终 YAML；当启用安全搜索时自动调整 DNS fake-ip-filter 列表。

### 3.3 静态资源与默认映射
- tauri.conf.json 的 bundle.resources 将 resources/mihomo/*.gz 和 resources/safe-search/*.yaml 打入安装包。
- safe-search/defaults.yaml 作为搜索引擎强制安全搜索的初始映射，随应用分发，可在运行期被覆盖或扩展。

## 4. 开发者应遵循的规则
1. 新增设置项：在 initialize_schema() 的 defaults 中插入默认值；在 allowed_setting() 白名单中添加 key 与合法值集合；在 read_settings() 中将其映射到 Settings 字段；在需要处使用 setting_bool(db, key) 读取。
2. 敏感信息：不要硬编码 secret，统一通过 external-controller + secret 传递，并确保不序列化进 YAML。
3. 配置变更生效：修改 settings 后如需影响内核，应在相应 Tauri command 中触发 reload_protection 或重启流程。
4. 资源文件：新增默认映射或规则集需同步更新 tauri.conf.json 的 bundle.resources 清单。
5. 权限与安全：涉及代理/TUN 的操作需走 platform::start_mihomo_privileged，避免直接 fork 子进程。