# CleanWeb Paper Prototype

This directory archives the Paper Design prototype used for the CleanWeb desktop and mobile UI work.

## Source

- Paper file: https://app.paper.design/file/01KYE5X58EYKG55M0VP84KHBMC/1-0/2WQ-0
- Paper title in local app tabs: `Versatile nova`
- Captured: 2026-07-26

The Paper file remains the editable source of truth inside Paper. The files in this directory are a GitHub-friendly reference snapshot so the design intent can be reviewed with the repository.

## Contents

- `paper-canvas-overview.png`: visible Paper canvas overview with desktop and mobile frames.
- `desktop-dashboard-zh.png`: focused crop of the Chinese desktop dashboard frame.
- `mobile-screens-zh.png`: top-band crop of the Chinese mobile frames.
- `paper-extracted-text.txt`: searchable text extracted from the Paper file view.

## Covered Frames

The Paper canvas includes desktop `1280x800` frames and mobile `390x844` frames for:

- Dashboard / Overview
- Rules
- Logs
- Subscriptions
- Proxy nodes
- Settings

The design follows the V1 product boundary:

- filtering decisions happen before proxy routing;
- logs and configuration are local-first;
- CleanWeb imports user-owned proxy subscriptions only;
- V1 does not provide cloud sync, remote monitoring, hosted proxy nodes, or HTTPS content inspection.
