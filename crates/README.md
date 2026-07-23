# CleanWeb Shared Crates

This directory is reserved for platform-independent Rust crates shared by desktop, Android, and future iOS integrations.

Do not put platform lifecycle or operating-system integration here. Keep `VpnService`, Network Extension, LaunchDaemon, Windows Service, systemd, Keychain, Keystore, DPAPI, Secret Service, installers, and UI code in platform app directories.

Current crates:

```text
crates/
  cleanweb-rules/            # Rule validation, normalization, matching, priority
```

Expected future crates:

```text
crates/
  cleanweb-core/             # Shared settings, categories, actions, log fields
  cleanweb-subscriptions/    # Rule/proxy/safe-search subscription parsing
  cleanweb-policy/           # Policy merge and action decisions
  cleanweb-mihomo-config/    # Mihomo config model and generation
  cleanweb-ffi/              # Android/iOS binding layer, only if needed
```

Create a crate only when two or more platforms need the same behavior or when extracting it from desktop reduces concrete duplication.
