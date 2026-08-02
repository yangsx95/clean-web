# CleanWeb Shared Resources

This directory contains resources that should be shared across platform apps, such as official rule packs, schemas, and test fixtures.

Current shared resources:

```text
resources/
  rule-sources/   # Official and recommended rule source metadata for publication
  rules/          # CleanWeb rule supplements for publication
```

Desktop-only runtime resources, such as bundled Mihomo binaries, remain under `apps/desktop/src-tauri/resources/` because Tauri packages them from that app-specific location. Desktop builds compile the shared rule source metadata from this directory, but rule supplement bodies are still imported through their subscription URLs instead of being bundled into executable rules.
