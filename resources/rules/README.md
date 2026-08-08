# CleanWeb 规则维护

这些文件是 CleanWeb 官方规则订阅的唯一内容入口。应用首次安装时使用安装包中的副本作为离线兜底；之后按 `resources/rule-sources/defaults.yaml` 中的地址和周期在线刷新。刷新成功会原子替换旧版本，失败则继续使用最后一次有效规则。

## 常用格式

```text
# 精确域名放行；必须写在同文件的宽泛拦截规则之前
DOMAIN,creator.example.com,DIRECT

# 精确域名拦截
DOMAIN,www.example.com,REJECT

# 域名及其所有子域名拦截
DOMAIN-SUFFIX,example.com,REJECT
```

- `DIRECT` 表示内容过滤放行并直连。
- `REJECT` 表示拦截。
- 精确例外放在宽泛后缀规则之前，便于 Mihomo 按顺序优先命中。
- 优先添加精确域名；确认服务确实会在整个后缀下动态分配主机后，再使用 `DOMAIN-SUFFIX`。
- 不要把厂商域名写进 Rust 或前端代码。

## 更新流程

1. 只修改本目录对应的 `.clash` 文件。
2. 运行 `npm run rules:check`。
3. 提交并推送到 `main`；客户端最迟在订阅周期到期后拉取，也可以在“内置规则”中点“检查更新”。

修改规则内容不需要重新打包应用。只有更改订阅地址、分类或新增规则文件时，才需要调整 `resources/rule-sources/defaults.yaml` 并发布应用版本。
