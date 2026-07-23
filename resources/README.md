# CleanWeb Shared Resources

This directory is reserved for resources that should be shared across platform apps, such as official rule packs, safe-search mappings, schemas, and test fixtures.

Current desktop runtime resources still live under `apps/desktop/src-tauri/resources/` because Tauri bundles them from that location. Move resources here only when the consuming platform build scripts are updated to package them explicitly.
