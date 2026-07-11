# CleanWeb V1 product specification

## Product statement

CleanWeb is a parental-control network filter for Windows and, later, macOS.
Content safety takes precedence over proxy routing. A parent controls all
policies and proxy choices; a child cannot change protection settings.

## V1 users and platform

- Primary environment: family-owned Windows computers.
- Administrator: parent holding the Windows administrator account and the
  CleanWeb management password.
- Managed user: child using a standard Windows account.
- macOS follows after the Windows architecture and rule engine are validated.

## Required capabilities

1. Capture device traffic using a TUN-based networking service.
2. Block domains, subdomains, IPs, and CIDRs using local rules.
3. Support exact, suffix, substring, wildcard, and regular-expression domain
   rules. Substring and regex rules are advanced features and may overblock.
4. Block core categories: pornography and suggestive content, gambling, drugs,
   graphic violence, self-harm, hate/extremism, fraud, phishing, and malware.
5. Offer optional categories including advertising, tracking, games, short
   video, live streaming, and social media.
6. Import Clash/Mihomo proxy nodes and proxy groups while rejecting imported
   DNS, routing, scripts, TUN settings, and bypass policies.
7. Automatically latency-test approved proxy nodes. Only a parent may select
   a node or change proxy behavior.
8. Import Clash/Mihomo providers, basic Adblock domain rules, hosts files,
   plain domain lists, and IP/CIDR lists. Unsupported cosmetic, script, and URL
   rules must be reported rather than silently treated as supported.
9. Enforce safe-search modes where supported for Google, Bing, YouTube,
   DuckDuckGo, Yahoo, Baidu, Sogou, 360 Search, and Yandex.
10. Start protection with Windows. Normal child actions cannot stop the service,
    change policy, or uninstall the product.

## Explicit V1 boundaries

- Unknown and newly registered domains are allowed by default.
- Unknown direct-IP connections are allowed, logged, and marked as warnings.
- IPs and CIDRs on a blocklist are blocked.
- HTTPS is not decrypted. Page text, images, video, full URL paths, and AI
  conversations are not inspected.
- A blocked connection fails normally; V1 does not provide an interstitial page.
- Service failure is fail-open: networking continues without filtering.
- Multiple managed OS accounts, remote cloud administration, access requests,
  OpenVPN coexistence, and VPN interoperability are outside V1.
- Administrator/root-level adversaries and service crashes are not within the
  anti-circumvention guarantee.

## Policy priority (highest first)

1. Product-integrity and anti-bypass policy
2. Malware, phishing, fraud, and other high-risk security rules
3. Parent blocklist
4. Parent allowlist
5. Core content-safety categories
6. Optional content categories
7. Third-party subscriptions
8. Proxy-routing policy
9. Default allow

A parent allowlist overrides content and subscription rules. It does not
override high-risk security rules unless an advanced administrative override is
explicitly enabled.

## Rule provenance and commercial safety

- Normalize semantically equivalent rules into one canonical record.
- Preserve every contributing source and category on that record.
- Removing a subscription removes only its source contribution.
- Bundle only sources whose licenses permit commercial redistribution.
- Store source URL, license, attribution, version, checksum, and update time.
- Sign first-party rule packages and retain the last valid version for rollback.
- User-added sources are clearly distinguished from bundled trusted sources.

## Access log

Each decision may record:

- Timestamp
- Observed domain, when available
- Target IP and port
- Allow/block/warning result
- Matching canonical rule and category
- Originating process
- Windows version
- Logged-in Windows user
- Direct connection or selected proxy group

Unknown direct-IP access receives a warning classification. Retention is
configurable up to 90 days or permanently. V1 stores logs locally.

## UX direction

The UI is calm, clean, and administrative rather than styled like a generic VPN
client. It has two states:

- Locked state: protection summary and non-sensitive status only.
- Management state: unlocked by parent credentials; rules, subscriptions,
  proxy nodes, logs, and settings are editable.

Destructive and protection-reducing actions require explicit confirmation.
