# Agent Instructions

## Project Context

CleanWeb is a Tauri + React + Rust desktop app for parental network filtering, proxy subscription import, local policy enforcement, access logs, and safe-search enforcement.

Before changing behavior, read the relevant product and architecture boundaries in:

- `docs/product-spec.md`
- `docs/architecture.md`

## Dependency Policy

Prefer existing, available dependencies over custom implementations.

Before writing new parsing, networking, cryptography, storage, UI, validation, or browser/system-integration logic:

1. Check whether the project already has a dependency, helper module, or platform abstraction that solves the problem.
2. Use the existing dependency or local abstraction when it is suitable.
3. Add a new dependency only when the standard library and current project dependencies do not cover the need cleanly.
4. Do not reimplement mature functionality such as YAML/JSON parsing, URL parsing, CIDR/IP handling, regex matching, encryption, hashing, HTTP clients, database access, or Tauri command plumbing.
5. If a custom implementation is still necessary, keep it small, isolated, documented by tests, and explain why an existing dependency was not appropriate.

## Implementation Guidelines

- Keep changes scoped to the requested behavior.
- Preserve existing frontend and Rust module boundaries.
- Prefer structured parsers and typed APIs over ad hoc string manipulation.
- Keep user-facing behavior aligned with the V1 product boundary.
- Avoid broad refactors unless they directly reduce risk for the requested change.
- Do not overwrite unrelated local changes.
- Do not fix routing or filtering false positives by hardcoding one-off vendor, cloud-provider, or user-specific allow rules. Prefer a general rule-priority, rule-model, or user-configurable routing solution, and document the reasoning in tests when behavior changes.

## Validation

Use the narrowest meaningful checks first, then broader checks before finishing:

```bash
npm test
npm run build
cd src-tauri && cargo test
cd src-tauri && cargo clippy --all-targets -- -D warnings
```

When changing UI layout, verify the running app visually at a relevant viewport size.
