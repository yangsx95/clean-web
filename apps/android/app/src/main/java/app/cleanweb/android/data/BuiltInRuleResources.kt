package app.cleanweb.android.data

import android.content.Context
import app.cleanweb.android.model.RuleAction
import app.cleanweb.android.model.RuleCategory
import app.cleanweb.android.model.RuleEntry
import app.cleanweb.android.model.RuleMatchKind
import java.io.File

object BuiltInRuleResources {
    private val resources = listOf(
        BuiltInRuleResource(
            path = "rules/cleanweb-adult-supplement.clash",
            idPrefix = "core-adult",
            category = RuleCategory.Core
        ),
        BuiltInRuleResource(
            path = "rules/cleanweb-security-supplement.clash",
            idPrefix = "core-security",
            category = RuleCategory.Core
        )
    )

    fun load(context: Context): List<RuleEntry> {
        return resources.flatMap { resource ->
            context.assets.open(resource.path).bufferedReader(Charsets.UTF_8).use { reader ->
                parseClashRules(resource, reader.readText())
            }
        }
    }

    fun loadFromResourceRoot(root: File): List<RuleEntry> {
        return resources.flatMap { resource ->
            parseClashRules(resource, root.resolve(resource.path).readText(Charsets.UTF_8))
        }
    }

    internal fun parseClashRules(resource: BuiltInRuleResource, text: String): List<RuleEntry> {
        return text.lineSequence()
            .mapIndexedNotNull { index, rawLine ->
                parseClashRuleLine(resource, index + 1, rawLine)
            }
            .toList()
    }

    private fun parseClashRuleLine(
        resource: BuiltInRuleResource,
        lineNumber: Int,
        rawLine: String
    ): RuleEntry? {
        val line = rawLine.substringBefore('#').trim()
        if (line.isBlank()) return null
        val parts = line.split(',').map { it.trim() }
        if (parts.size < 3 || !parts[2].equals("REJECT", ignoreCase = true)) return null
        val pattern = parts[1].trimStart('.').trimEnd('.').lowercase()
        if (pattern.isBlank() || pattern.any { it.isWhitespace() } || pattern.contains(',')) return null
        val matchKind = when (parts[0].uppercase()) {
            "DOMAIN" -> RuleMatchKind.Exact
            "DOMAIN-SUFFIX" -> RuleMatchKind.Suffix
            "DOMAIN-KEYWORD" -> RuleMatchKind.Keyword
            "IP-CIDR", "IP-CIDR6" -> RuleMatchKind.Cidr
            else -> return null
        }
        return RuleEntry(
            id = "${resource.idPrefix}-$lineNumber",
            pattern = pattern,
            category = resource.category,
            action = RuleAction.Block,
            matchKind = matchKind
        )
    }
}

data class BuiltInRuleResource(
    val path: String,
    val idPrefix: String,
    val category: RuleCategory
)
