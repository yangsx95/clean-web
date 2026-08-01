package app.cleanweb.android.vpn

import app.cleanweb.android.data.BuiltInRuleResources
import app.cleanweb.android.data.ProxyConfigSanitizer
import app.cleanweb.android.model.CleanWebState
import app.cleanweb.android.model.ProtectionSettings
import app.cleanweb.android.model.ProxySubscription
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.model.RuleMatchKind
import app.cleanweb.android.model.normalizeBuiltInRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.yaml.snakeyaml.Yaml
import java.io.File

class MihomoAndroidConfigTest {
    @Test
    fun defaultStateIncludesRealBuiltInBlockRules() {
        val config = MihomoAndroidConfig.build(CleanWebState(rules = sharedBuiltInRules()))

        assertTrue(config.contains("  - DOMAIN-SUFFIX,pornhub.com,REJECT"))
        assertTrue(config.contains("  - DOMAIN-SUFFIX,18j.tv,REJECT"))
        assertTrue(config.contains("  - DOMAIN-SUFFIX,dh.net,REJECT"))
        assertTrue(config.contains("  - DOMAIN-SUFFIX,dns.google,REJECT"))
        assertFalse(config.contains("adult.example"))
    }

    @Test
    fun androidTun2socksConfigSniffsPureIpTrafficForDomainRules() {
        val config = MihomoAndroidConfig.build(CleanWebState(rules = sharedBuiltInRules()))

        assertTrue(config.contains("  parse-pure-ip: true"))
        assertTrue(config.contains("  force-dns-mapping: true"))
        assertTrue(config.contains("    QUIC:"))
    }

    @Test
    fun googleSafeSearchUsesVipAddressMapping() {
        val config = MihomoAndroidConfig.build(CleanWebState(rules = sharedBuiltInRules()))

        assertTrue(config.contains("  www.google.com: 216.239.38.120"))
        assertFalse(config.contains("  www.google.com: forcesafesearch.google.com"))
    }

    @Test
    fun normalizesLegacyPlaceholderBuiltInRules() {
        val builtInRules = sharedBuiltInRules()
        val normalized = normalizeBuiltInRules(
            listOf(
                RuleEntry("core-adult", "adult.example", RuleCategory.Core, RuleAction.Block),
                RuleEntry("custom", "custom.example", RuleCategory.CustomBlock, RuleAction.Block)
            ),
            builtInRules
        )

        assertTrue(normalized.any { it.pattern == "pornhub.com" })
        assertTrue(normalized.any { it.pattern == "custom.example" })
        assertFalse(normalized.any { it.pattern == "adult.example" })
    }

    @Test
    fun configIsValidYamlWithProxyProviderAndRules() {
        val config = MihomoAndroidConfig.build(
            CleanWebState(
                settings = ProtectionSettings(proxyEnabled = true),
                proxySubscriptions = listOf(
                    ProxySubscription(
                        id = "12345678-android",
                        name = "Test",
                        url = "https://example.com/sub.yaml"
                    )
                ),
                rules = listOf(
                    RuleEntry("block", "blocked.example", RuleCategory.CustomBlock, RuleAction.Block),
                    RuleEntry("allow", "allowed.example", RuleCategory.CustomAllow, RuleAction.Allow),
                    RuleEntry("core", "pornhub.com", RuleCategory.Core, RuleAction.Block),
                    RuleEntry("cidr", "203.0.113.0/24", RuleCategory.CustomBlock, RuleAction.Block)
                )
            )
        )

        val yaml = Yaml().load<Map<String, Any>>(config)

        assertEquals(17890, yaml["mixed-port"])
        assertTrue(config.contains("provider_1_12345678"))
        assertTrue(config.contains("  - DOMAIN-SUFFIX,pornhub.com,REJECT"))
        assertTrue(config.contains("  - IP-CIDR,203.0.113.0/24,REJECT,no-resolve"))
        assertTrue(config.contains("  - MATCH,CLEANWEB-PROXY"))
    }

    @Test
    fun routeRulesSupportDesktopEquivalentActionsAndMatchKinds() {
        val config = MihomoAndroidConfig.build(
            CleanWebState(
                settings = ProtectionSettings(proxyEnabled = true),
                proxySubscriptions = listOf(
                    ProxySubscription(
                        id = "12345678-android",
                        name = "Test",
                        url = "https://example.com/sub.yaml"
                    )
                ),
                rules = listOf(
                    RuleEntry(
                        id = "exact-direct",
                        pattern = "api.example.com",
                        category = RuleCategory.Routing,
                        action = RuleAction.Allow,
                        matchKind = RuleMatchKind.Exact
                    ),
                    RuleEntry(
                        id = "keyword-proxy",
                        pattern = "github",
                        category = RuleCategory.Routing,
                        action = RuleAction.Proxy,
                        matchKind = RuleMatchKind.Keyword
                    ),
                    RuleEntry(
                        id = "system-route",
                        pattern = "10.8.0.0/24",
                        category = RuleCategory.Routing,
                        action = RuleAction.SystemRoute,
                        matchKind = RuleMatchKind.Cidr
                    )
                )
            )
        )

        assertTrue(config.contains("  - DOMAIN,api.example.com,DIRECT"))
        assertTrue(config.contains("  - DOMAIN-KEYWORD,github,CLEANWEB-PROXY"))
        assertTrue(config.contains("  - IP-CIDR,10.8.0.0/24,DIRECT"))
    }

    @Test
    fun routingRulesProxyChatGptDownloadDomainsWhenProxyIsEnabled() {
        val config = MihomoAndroidConfig.build(
            CleanWebState(
                settings = ProtectionSettings(proxyEnabled = true),
                proxySubscriptions = listOf(
                    ProxySubscription(
                        id = "12345678-android",
                        name = "Test",
                        url = "https://example.com/sub.yaml"
                    )
                ),
                rules = listOf(
                    RuleEntry(
                        id = "chatgpt-download",
                        pattern = "persistent.oaistatic.com",
                        category = RuleCategory.Routing,
                        action = RuleAction.Proxy
                    )
                )
            )
        )

        assertTrue(config.contains("  - DOMAIN-SUFFIX,persistent.oaistatic.com,CLEANWEB-PROXY"))
        assertFalse(config.contains("  - DOMAIN-SUFFIX,persistent.oaistatic.com,REJECT"))
    }

    @Test
    fun proxyDisabledFallsBackToDirect() {
        val config = MihomoAndroidConfig.build(
            CleanWebState(
                settings = ProtectionSettings(proxyEnabled = false),
                proxySubscriptions = listOf(
                    ProxySubscription(
                        id = "12345678-android",
                        name = "Test",
                        url = "https://example.com/sub.yaml"
                    )
                )
            )
        )

        assertTrue(config.contains("proxy-providers: {}"))
        assertTrue(config.contains("proxy-groups: []"))
        assertTrue(config.contains("  - MATCH,DIRECT"))
    }

    @Test
    fun proxyEnabledDoesNotDefaultToDirect() {
        val config = MihomoAndroidConfig.build(
            CleanWebState(
                settings = ProtectionSettings(proxyEnabled = true),
                proxySubscriptions = listOf(
                    ProxySubscription(
                        id = "12345678-android",
                        name = "Test",
                        url = "https://example.com/sub.yaml"
                    )
                )
            )
        )

        val proxyGroup = config.substringAfter("proxy-groups:").substringBefore("rules:")

        assertFalse(proxyGroup.contains("      - DIRECT"))
        assertTrue(config.contains("  - MATCH,CLEANWEB-PROXY"))
    }

    @Test
    fun localProxyConfigUsesFileProvider() {
        val config = MihomoAndroidConfig.build(
            CleanWebState(
                settings = ProtectionSettings(proxyEnabled = true),
                proxySubscriptions = listOf(
                    ProxySubscription(
                        id = "12345678-android",
                        name = "Local",
                        url = "file://cleanweb-providers/local_12345678_android.yaml",
                        importedNodeCount = 1,
                        localProviderFileName = "local_12345678_android.yaml"
                    )
                )
            )
        )

        assertTrue(config.contains("    type: file"))
        assertTrue(config.contains("    path: './providers/local_12345678_android.yaml'"))
        assertTrue(config.contains("      - provider_1_12345678"))
    }

    @Test
    fun proxyConfigImportStripsRuntimeFields() {
        val sanitized = ProxyConfigSanitizer.sanitize(
            """
            proxies:
              - {name: a, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-128-gcm, password: p}
            proxy-groups:
              - {name: auto, type: select, proxies: [a]}
            rules:
              - MATCH,DIRECT
            dns:
              enable: true
            tun:
              enable: true
            """.trimIndent()
        )

        assertEquals(1, sanitized.proxyCount)
        assertEquals(1, sanitized.groupCount)
        assertTrue(sanitized.payload.contains("proxies"))
        assertFalse(sanitized.payload.contains("rules:"))
        assertFalse(sanitized.payload.contains("dns:"))
        assertFalse(sanitized.payload.contains("tun:"))
    }

    @Test
    fun proxyConfigImportAcceptsLongUnicodeFlowStyleNodes() {
        val longServer = "a".repeat(340) + ".example.com"
        val sanitized = ProxyConfigSanitizer.sanitize(
            """
            proxies:
              - {name: 🇯🇵 日本A01 | IEPL, server: $longServer, port: 476, type: ss, cipher: aes-256-gcm, password: password-token, udp: true}
            proxy-groups:
              - name: 🔰 选择节点
                type: select
                proxies:
                  - 🇯🇵 日本A01 | IEPL
            rules:
              - MATCH,DIRECT
            """.trimIndent()
        )

        assertEquals(1, sanitized.proxyCount)
        assertTrue(sanitized.payload.contains("日本A01"))
    }

    @Test
    fun adsRulesFollowAdsTrackingToggle() {
        val state = CleanWebState(
            settings = ProtectionSettings(adsTrackingEnabled = false),
            rules = listOf(
                RuleEntry("ads", "tracker.example", RuleCategory.AdsTracking, RuleAction.Block)
            )
        )

        val config = MihomoAndroidConfig.build(state)

        assertTrue(!config.contains("tracker.example"))
    }

    @Test
    fun strictModeRulesComeFromSharedSupplementOnlyWhenEnabled() {
        val disabled = CleanWebState(
            settings = ProtectionSettings(strictModeEnabled = false),
            strictModeRules = sharedStrictModeRules()
        )
        val disabledConfig = MihomoAndroidConfig.build(disabled)

        assertFalse(disabledConfig.contains("DOMAIN-SUFFIX,youtube.com,REJECT"))
        assertFalse(disabledConfig.contains("DOMAIN-KEYWORD,xvideo,REJECT"))

        val enabled = disabled.copy(settings = disabled.settings.copy(strictModeEnabled = true))
        val enabledConfig = MihomoAndroidConfig.build(enabled)

        assertTrue(enabledConfig.contains("DOMAIN-SUFFIX,youtube.com,REJECT"))
        assertTrue(enabledConfig.contains("DOMAIN-KEYWORD,xvideo,REJECT"))
        assertTrue(enabledConfig.contains("DOMAIN-KEYWORD,casino,REJECT"))
        listOf("vip", "cc", "fun").forEach { suffix ->
            assertFalse(enabledConfig.contains("DOMAIN-SUFFIX,$suffix,REJECT"))
        }
    }

    @Test
    fun entertainmentRulesFollowEntertainmentToggle() {
        val disabled = CleanWebState(
            settings = ProtectionSettings(entertainmentEnabled = false),
            rules = listOf(
                RuleEntry("game", "game.example", RuleCategory.Entertainment, RuleAction.Block),
                RuleEntry("allow-douyin", "douyin.com", RuleCategory.CustomAllow, RuleAction.Allow, RuleMatchKind.Exact),
                RuleEntry("proxy-roblox", "roblox.com", RuleCategory.Routing, RuleAction.Proxy)
            )
        )

        val disabledConfig = MihomoAndroidConfig.build(disabled)

        assertTrue(!disabledConfig.contains("DOMAIN-SUFFIX,douyin.com,REJECT"))
        assertTrue(!disabledConfig.contains("DOMAIN-SUFFIX,douyinvod.com,REJECT"))
        assertTrue(!disabledConfig.contains("DOMAIN-SUFFIX,bilivideo.cn,REJECT"))
        assertTrue(!disabledConfig.contains("game.example"))

        val enabled = disabled.copy(settings = disabled.settings.copy(entertainmentEnabled = true))
        val enabledConfig = MihomoAndroidConfig.build(enabled)

        assertTrue(enabledConfig.contains("DOMAIN-SUFFIX,douyin.com,REJECT"))
        assertTrue(enabledConfig.contains("DOMAIN-SUFFIX,douyinvod.com,REJECT"))
        assertTrue(enabledConfig.contains("DOMAIN-SUFFIX,bilivideo.cn,REJECT"))
        assertTrue(enabledConfig.contains("DOMAIN-SUFFIX,game.example,REJECT"))
        assertTrue(enabledConfig.indexOf("DOMAIN,douyin.com,DIRECT") < enabledConfig.indexOf("DOMAIN-SUFFIX,douyin.com,REJECT"))
        assertTrue(enabledConfig.indexOf("DOMAIN-SUFFIX,roblox.com,REJECT") < enabledConfig.indexOf("DOMAIN-SUFFIX,roblox.com,DIRECT"))
    }

    private fun sharedBuiltInRules() = BuiltInRuleResources.loadFromResourceRoot(resourceRoot())

    private fun sharedStrictModeRules() = BuiltInRuleResources.loadStrictModeFromResourceRoot(resourceRoot())

    private fun resourceRoot(): File {
        return listOf(
            File("../../resources"),
            File("../../../resources"),
            File("resources")
        ).first { it.resolve("rules/cleanweb-adult-supplement.clash").isFile }
    }
}
