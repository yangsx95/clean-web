package app.cleanweb.android.vpn

import app.cleanweb.android.data.ProxyConfigSanitizer
import app.cleanweb.android.model.CleanWebState
import app.cleanweb.android.model.ProtectionSettings
import app.cleanweb.android.model.ProxySubscription
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.model.RuleMatchKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.yaml.snakeyaml.Yaml

class MihomoAndroidConfigTest {
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
                    RuleEntry("core", "adult.example", RuleCategory.Core, RuleAction.Block),
                    RuleEntry("cidr", "203.0.113.0/24", RuleCategory.CustomBlock, RuleAction.Block)
                )
            )
        )

        val yaml = Yaml().load<Map<String, Any>>(config)

        assertEquals(17890, yaml["mixed-port"])
        assertTrue(config.contains("provider_1_12345678"))
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
                    )
                )
            )
        )

        assertTrue(config.contains("  - DOMAIN,api.example.com,DIRECT"))
        assertTrue(config.contains("  - DOMAIN-KEYWORD,github,CLEANWEB-PROXY"))
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
}
