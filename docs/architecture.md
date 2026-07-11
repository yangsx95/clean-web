# CleanWeb V1 architecture

## Components

### Desktop UI

Tauri 2 with React and TypeScript provides the Windows management client. The
UI never edits generated proxy configuration directly; it calls a narrow set of
typed service commands.

### Privileged Windows service

A Rust service owns policy storage, rule compilation, logging, lifecycle checks,
and communication with the networking core. It runs independently of the UI so
closing the window does not stop protection.

### Rule engine

The rule engine converts imported formats into canonical records, maintains
source provenance, compiles indexes, and returns a deterministic decision with
an explanation. Exact and suffix indexes are evaluated before expensive
wildcard and regex rules.

### Proxy core boundary

Mihomo is treated as a separately distributed GPLv3 program and controlled via
configuration and its documented external API. CleanWeb extracts only nodes and
proxy groups from subscriptions, then generates its own locked DNS, TUN, filter,
and routing configuration.

This separation reduces coupling but does not replace a release-time open-source
license review. The product must provide all notices and corresponding source
required for the exact Mihomo binary it distributes.

### Storage

SQLite stores policies, canonical rules, source references, subscriptions,
proxy metadata, and access logs. Secrets are encrypted using Windows DPAPI.

## Windows networking direction

The first prototype uses Mihomo TUN for traffic capture and proxy protocols.
CleanWeb remains the policy authority. A later hardening phase should evaluate a
Windows Filtering Platform callout/service for stronger process identity and
anti-bypass enforcement.

## Fail-open behavior

The agreed V1 behavior allows networking when CleanWeb or its filtering core is
unavailable. The UI must describe this accurately and show whether protection is
currently active; V1 makes no remote failure notification guarantee.
