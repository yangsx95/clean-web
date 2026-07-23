package app.cleanweb.android.vpn

import app.cleanweb.android.model.CleanWebState
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import java.net.URI

internal object MihomoAndroidConfig {
    private const val PROXY_GROUP_NAME = "CLEANWEB-PROXY"

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

    private fun MutableList<Pair<String, String>>.addProvider(index: Int, id: String, url: String) {
        val name = "provider_${index + 1}_${id.take(8).replace("-", "_")}"
        add(name to url)
    }

    private fun proxyProviders(state: CleanWebState): List<Pair<String, String>> {
        if (!state.settings.proxyEnabled) {
            return emptyList()
        }
        return buildList {
            state.proxySubscriptions
                .filter { it.enabled && isHttpsUrl(it.url) }
                .forEachIndexed { index, subscription ->
                    addProvider(index, subscription.id, subscription.url)
                }
        }
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
        appendLine("  sniff:")
        listOf("HTTP" to listOf("80", "8080-8880"), "TLS" to listOf("443", "8443")).forEach { (name, ports) ->
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

    private fun StringBuilder.appendProxyProviders(providers: List<Pair<String, String>>) {
        if (providers.isEmpty()) {
            appendLine("proxy-providers: {}")
            return
        }
        appendLine("proxy-providers:")
        providers.forEach { (name, url) ->
            appendLine("  $name:")
            appendLine("    type: http")
            appendLine("    url: ${yamlQuote(url)}")
            appendLine("    interval: 3600")
            appendLine("    path: ./providers/$name.yaml")
            appendLine("    health-check:")
            appendLine("      enable: true")
            appendLine("      interval: 600")
            appendLine("      url: https://www.gstatic.com/generate_204")
        }
    }

    private fun StringBuilder.appendProxyGroups(providers: List<Pair<String, String>>) {
        if (providers.isEmpty()) {
            appendLine("proxy-groups: []")
            return
        }
        appendLine("proxy-groups:")
        appendLine("  - name: $PROXY_GROUP_NAME")
        appendLine("    type: select")
        appendLine("    proxies:")
        appendLine("      - DIRECT")
        appendLine("    use:")
        providers.forEach { (name, _) -> appendLine("      - $name") }
    }

    private fun StringBuilder.appendRules(state: CleanWebState, finalPolicy: String) {
        appendLine("rules:")
        state.rules
            .filter { it.enabled && it.action == RuleAction.Block && it.category == RuleCategory.CustomBlock }
            .mapNotNull { mihomoRule(it.pattern, "REJECT") }
            .forEach { appendLine("  - $it") }
        state.rules
            .filter { it.enabled && it.action == RuleAction.Allow }
            .mapNotNull { mihomoRule(it.pattern, "DIRECT") }
            .forEach { appendLine("  - $it") }
        state.rules
            .filter { it.enabled && it.action == RuleAction.Block && it.category == RuleCategory.Core }
            .mapNotNull { mihomoRule(it.pattern, "REJECT") }
            .forEach { appendLine("  - $it") }
        if (state.settings.strictModeEnabled) {
            strictModeSuffixes.forEach { suffix -> appendLine("  - DOMAIN-SUFFIX,$suffix,REJECT") }
        }
        if (state.settings.adsTrackingEnabled) {
            state.rules
                .filter { it.enabled && it.action == RuleAction.Block && it.category == RuleCategory.AdsTracking }
                .mapNotNull { mihomoRule(it.pattern, "REJECT") }
                .forEach { appendLine("  - $it") }
        }
        localDirectRules.forEach { appendLine("  - $it") }
        appendLine("  - MATCH,$finalPolicy")
    }

    private fun mihomoRule(pattern: String, policy: String): String? {
        val normalized = pattern.trim().trimStart('.').trimEnd('.').lowercase()
        if (normalized.isBlank()) {
            return null
        }
        if (normalized.contains(",")) {
            return null
        }
        if (normalized.contains("/")) {
            val kind = if (normalized.contains(":")) "IP-CIDR6" else "IP-CIDR"
            return "$kind,$normalized,$policy,no-resolve"
        }
        if (normalized.any { it.isWhitespace() }) {
            return null
        }
        return "DOMAIN-SUFFIX,$normalized,$policy"
    }

    private fun yamlQuote(value: String): String {
        return "'${value.replace("'", "''")}'"
    }

    private data class SafeSearchMapping(val domain: String, val target: String)

    private val safeSearchMappings = listOf(
        SafeSearchMapping("www.google.com", "forcesafesearch.google.com"),
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

    private val strictModeSuffixes = listOf(
        "yandex.com",
        "yandex.ru",
        "yandex.net",
        "youtu.be",
        "youtube.com"
    )
}
