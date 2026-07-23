# CleanWeb Shared Resources

This directory contains resources that should be shared across platform apps, such as official rule packs, safe-search mappings, schemas, and test fixtures.

Current shared resources:

```text
resources/
  rules/          # Built-in CleanWeb rule supplements
  safe-search/    # Built-in safe-search provider mappings
```

Desktop-only runtime resources, such as bundled Mihomo binaries, remain under `apps/desktop/src-tauri/resources/` because Tauri packages them from that app-specific location.
