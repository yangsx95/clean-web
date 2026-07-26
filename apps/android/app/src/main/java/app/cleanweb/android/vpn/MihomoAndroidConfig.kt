package app.cleanweb.android.vpn

import app.cleanweb.android.model.CleanWebState
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.model.RuleMatchKind
import java.net.URI

internal object MihomoAndroidConfig {
    private const val PROXY_GROUP_NAME = "CLEANWEB-PROXY"
    private data class ProxyProvider(val name: String, val type: String, val value: String)

    fun build(state: CleanWebState): String {
        val providers = proxyProviders(state)
        val finalPolicy = if (providers.isEmpty()) "DIRECT" else PROXY_GROUP_NAME

        return buildString {
            appendLine("mixed-port: 17890")
            appendLine("allow-lan: false")
            appendLine("mode: rule")
            appendLine("log-level: info")
            appendLine("ipv6: false")
            appendLine("external-controller: 127.0.0.1:17891")
            appendSniffer(state)
            appendDns(state)
            appendLine("proxies: []")
            appendProxyProviders(providers)
            appendProxyGroups(providers)
            appendRules(state, finalPolicy)
        }.trimEnd() + "\n"
    }

    private fun MutableList<ProxyProvider>.addRemoteProvider(index: Int, id: String, url: String) {
        val name = "provider_${index + 1}_${id.take(8).replace("-", "_")}"
        add(ProxyProvider(name = name, type = "http", value = url))
    }

    private fun MutableList<ProxyProvider>.addLocalProvider(index: Int, id: String, fileName: String) {
        val name = "provider_${index + 1}_${id.take(8).replace("-", "_")}"
        add(ProxyProvider(name = name, type = "file", value = "./providers/$fileName"))
    }

    private fun proxyProviders(state: CleanWebState): List<ProxyProvider> {
        if (!state.settings.proxyEnabled) {
            return emptyList()
        }
        return buildList {
            state.proxySubscriptions
                .filter { it.enabled && (isHttpsUrl(it.url) || isLocalProvider(it.localProviderFileName)) }
                .forEachIndexed { index, subscription ->
                    val fileName = subscription.localProviderFileName
                    if (fileName != null) {
                        addLocalProvider(index, subscription.id, fileName)
                    } else {
                        addRemoteProvider(index, subscription.id, subscription.url)
                    }
                }
        }
    }

    private fun isLocalProvider(fileName: String?): Boolean {
        return fileName?.matches(Regex("""local_[A-Za-z0-9_]+[.]yaml""")) == true
    }

    private fun isHttpsUrl(value: String): Boolean {
        return runCatching {
            val uri = URI(value)
            uri.scheme == "https" && !uri.host.isNullOrBlank()
        }.getOrDefault(false)
    }

    private fun StringBuilder.appendSniffer(state: CleanWebState) {
        appendLine("sniffer:")
        appendLine("  enable: true")
        appendLine("  force-dns-mapping: true")
        appendLine("  parse-pure-ip: true")
        appendLine("  override-destination: true")
        appendLine("  sniff:")
        listOf(
            "HTTP" to listOf("80", "8080-8880"),
            "TLS" to listOf("443", "8443"),
            "QUIC" to listOf("443", "8443")
        ).forEach { (name, ports) ->
            appendLine("    $name:")
            appendLine("      ports:")
            ports.forEach { port -> appendLine("        - $port") }
            appendLine("      override-destination: true")
        }
        if (state.settings.safeSearchEnabled) {
            appendLine("  skip-domain:")
            safeSearchMappings.forEach { mapping ->
                appendLine("    - ${mapping.domain}")
                appendLine("    - ${mapping.target}")
            }
        }
    }

    private fun StringBuilder.appendDns(state: CleanWebState) {
        appendLine("dns:")
        appendLine("  enable: true")
        appendLine("  listen: 127.0.0.1:17853")
        appendLine("  enhanced-mode: fake-ip")
        appendLine("  fake-ip-range: 198.18.0.1/16")
        appendLine("  respect-rules: true")
        appendLine("  use-hosts: true")
        appendLine("  nameserver:")
        appendLine("    - 223.5.5.5")
        appendLine("    - 119.29.29.29")
        appendLine("  direct-nameserver:")
        appendLine("    - 223.5.5.5")
        appendLine("    - 119.29.29.29")
        appendLine("  proxy-server-nameserver:")
        appendLine("    - 223.5.5.5")
        appendLine("    - 119.29.29.29")
        appendLine("  fake-ip-filter:")
        localFakeIpFilters.forEach { filter -> appendLine("    - $filter") }
        if (state.settings.safeSearchEnabled) {
            safeSearchMappings.forEach { mapping ->
                appendLine("    - ${mapping.domain}")
                appendLine("    - ${mapping.target}")
            }
            appendLine("hosts:")
            safeSearchMappings.forEach { mapping ->
                appendLine("  ${mapping.domain}: ${mapping.target}")
            }
        }
    }

    private fun StringBuilder.appendProxyProviders(providers: List<ProxyProvider>) {
        if (providers.isEmpty()) {
            appendLine("proxy-providers: {}")
            return
        }
        appendLine("proxy-providers:")
        providers.forEach { provider ->
            appendLine("  ${provider.name}:")
            appendLine("    type: ${provider.type}")
            if (provider.type == "http") {
                appendLine("    url: ${yamlQuote(provider.value)}")
                appendLine("    interval: 3600")
                appendLine("    path: ./providers/${provider.name}.yaml")
                appendLine("    health-check:")
                appendLine("      enable: true")
                appendLine("      interval: 600")
                appendLine("      url: https://www.gstatic.com/generate_204")
            } else {
                appendLine("    path: ${yamlQuote(provider.value)}")
                appendLine("    health-check:")
                appendLine("      enable: true")
                appendLine("      interval: 600")
                appendLine("      url: https://www.gstatic.com/generate_204")
            }
        }
    }

    private fun StringBuilder.appendProxyGroups(providers: List<ProxyProvider>) {
        if (providers.isEmpty()) {
            appendLine("proxy-groups: []")
            return
        }
        appendLine("proxy-groups:")
        appendLine("  - name: $PROXY_GROUP_NAME")
        appendLine("    type: select")
        appendLine("    use:")
        providers.forEach { provider -> appendLine("      - ${provider.name}") }
    }

    private fun StringBuilder.appendRules(state: CleanWebState, finalPolicy: String) {
        appendLine("rules:")
        state.rules
            .filter { it.enabled && it.action == RuleAction.Block && it.category == RuleCategory.CustomBlock }
            .mapNotNull { mihomoRule(it, "REJECT") }
            .forEach { appendLine("  - $it") }
        state.rules
            .filter { it.enabled && it.action == RuleAction.Allow }
            .mapNotNull { mihomoRule(it, "DIRECT") }
            .forEach { appendLine("  - $it") }
        state.rules
            .filter { it.enabled && it.action == RuleAction.Block && it.category == RuleCategory.Core }
            .mapNotNull { mihomoRule(it, "REJECT") }
            .forEach { appendLine("  - $it") }
        if (state.settings.strictModeEnabled) {
            state.strictModeRules
                .filter { it.enabled && it.action == RuleAction.Block }
                .mapNotNull { mihomoRule(it, "REJECT") }
                .forEach { appendLine("  - $it") }
        }
        if (state.settings.adsTrackingEnabled) {
            state.rules
                .filter { it.enabled && it.action == RuleAction.Block && it.category == RuleCategory.AdsTracking }
                .mapNotNull { mihomoRule(it, "REJECT") }
                .forEach { appendLine("  - $it") }
        }
        if (state.settings.entertainmentEnabled) {
            entertainmentSuffixes.forEach { suffix -> appendLine("  - DOMAIN-SUFFIX,$suffix,REJECT") }
            entertainmentKeywords.forEach { keyword -> appendLine("  - DOMAIN-KEYWORD,$keyword,REJECT") }
            state.rules
                .filter { it.enabled && it.action == RuleAction.Block && it.category == RuleCategory.Entertainment }
                .mapNotNull { mihomoRule(it, "REJECT") }
                .forEach { appendLine("  - $it") }
        }
        state.rules
            .filter { it.enabled && it.action == RuleAction.Proxy }
            .mapNotNull { mihomoRule(it, finalPolicy) }
            .forEach { appendLine("  - $it") }
        localDirectRules.forEach { appendLine("  - $it") }
        appendLine("  - MATCH,$finalPolicy")
    }

    private fun mihomoRule(rule: RuleEntry, policy: String): String? {
        return mihomoRule(rule.pattern, policy, rule.matchKind)
    }

    private fun mihomoRule(
        pattern: String,
        policy: String,
        matchKind: RuleMatchKind = RuleMatchKind.Suffix
    ): String? {
        val normalized = pattern.trim().trimStart('.').trimEnd('.').lowercase()
        if (normalized.isBlank()) {
            return null
        }
        if (normalized.contains(",")) {
            return null
        }
        if (normalized.any { it.isWhitespace() }) {
            return null
        }
        return when (matchKind) {
            RuleMatchKind.Cidr -> {
                if (!normalized.contains("/")) return null
                val kind = if (normalized.contains(":")) "IP-CIDR6" else "IP-CIDR"
                "$kind,$normalized,$policy,no-resolve"
            }
            RuleMatchKind.Exact -> "DOMAIN,$normalized,$policy"
            RuleMatchKind.Keyword -> "DOMAIN-KEYWORD,$normalized,$policy"
            RuleMatchKind.Suffix -> {
                if (normalized.contains("/")) {
                    val kind = if (normalized.contains(":")) "IP-CIDR6" else "IP-CIDR"
                    "$kind,$normalized,$policy,no-resolve"
                } else {
                    "DOMAIN-SUFFIX,$normalized,$policy"
                }
            }
        }
    }

    private fun yamlQuote(value: String): String {
        return "'${value.replace("'", "''")}'"
    }

    private data class SafeSearchMapping(
        val domain: String,
        val target: String
    )

    private val safeSearchMappings = listOf(
        SafeSearchMapping("www.google.com", "216.239.38.120"),
        SafeSearchMapping("www.bing.com", "strict.bing.com"),
        SafeSearchMapping("duckduckgo.com", "safe.duckduckgo.com"),
        SafeSearchMapping("www.youtube.com", "restrict.youtube.com"),
        SafeSearchMapping("m.youtube.com", "restrict.youtube.com")
    )

    private val localFakeIpFilters = listOf(
        "+.home",
        "+.local",
        "+.lan",
        "+.internal",
        "+.arpa",
        "+.msftconnecttest.com",
        "+.msftncsi.com"
    )

    private val localDirectRules = listOf(
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
        "IP-CIDR6,fd00::/8,DIRECT,no-resolve",
        "DOMAIN-SUFFIX,home,DIRECT",
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "DOMAIN-SUFFIX,internal,DIRECT"
    )

    private val entertainmentSuffixes = listOf(
        "douyin.com",
        "douyinpic.com",
        "douyincdn.com",
        "douyinvod.com",
        "iesdouyin.com",
        "snssdk.com",
        "amemv.com",
        "pstatp.com",
        "bytecdn.cn",
        "byteimg.com",
        "bytedance.com",
        "bytedance.net",
        "zijieapi.com",
        "tiktok.com",
        "tiktokv.com",
        "tiktokcdn.com",
        "kuaishou.com",
        "gifshow.com",
        "ksapisrv.com",
        "yximgs.com",
        "bilibili.com",
        "bilivideo.com",
        "bilivideo.cn",
        "hdslb.com",
        "huya.com",
        "douyu.com",
        "xiaohongshu.com",
        "xhscdn.com",
        "youtube.com",
        "googlevideo.com",
        "ytimg.com",
        "roblox.com",
        "rbxcdn.com",
        "steamcommunity.com",
        "steampowered.com",
        "discord.com",
        "discord.gg",
        "twitch.tv"
    )

    private val entertainmentKeywords = listOf(
        "shortvideo",
        "short-video",
        "livestream",
        "mobilegame",
        "gamevideo"
    )
}
