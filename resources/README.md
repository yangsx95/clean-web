# CleanWeb Shared Resources

This directory contains resources that should be shared across platform apps, such as official rule packs, safe-search mappings, schemas, and test fixtures.

Current shared resources:

```text
resources/
  rule-sources/   # Official and recommended rule source metadata for publication
  rules/          # CleanWeb rule supplements for publication
  safe-search/    # Built-in safe-search provider mappings
```

Desktop-only runtime resources, such as bundled Mihomo binaries, remain under `apps/desktop/src-tauri/resources/` because Tauri packages them from that app-specific location. Desktop builds do not package or compile the rule source metadata and CleanWeb rule supplements under this top-level `resources/` directory.
