package app.cleanweb.android.data

import org.yaml.snakeyaml.Yaml

data class SanitizedProxyConfig(
    val payload: String,
    val proxyCount: Int,
    val groupCount: Int
)

object ProxyConfigSanitizer {
    private const val MAX_CONFIG_BYTES = 20 * 1024 * 1024

    fun sanitize(text: String): SanitizedProxyConfig {
        val content = text.trim()
        require(content.isNotEmpty()) { "配置文件不能为空" }
        require(content.toByteArray(Charsets.UTF_8).size <= MAX_CONFIG_BYTES) {
            "配置文件超过20MB限制"
        }

        val root = runCatching { Yaml().load<Any?>(content) }
            .getOrElse { throw IllegalArgumentException("配置文件不是有效 YAML：${it.message}") }
        require(root is Map<*, *>) { "配置文件必须是 Clash/Mihomo YAML" }

        val proxies = root["proxies"]
        val groups = root["proxy-groups"]
        val proxyCount = (proxies as? List<*>)?.size ?: 0
        val groupCount = (groups as? List<*>)?.size ?: 0
        require(proxyCount > 0) { "配置文件未包含可用代理节点" }

        val clean = linkedMapOf<String, Any?>("proxies" to proxies)
        return SanitizedProxyConfig(
            payload = Yaml().dump(clean),
            proxyCount = proxyCount,
            groupCount = groupCount
        )
    }
}
