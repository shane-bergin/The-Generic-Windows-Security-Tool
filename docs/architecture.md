# TGWST Architecture

## Shape

- `src/TGWST.App`: WPF GUI, MVVM view models, active dashboard services, tray status.
- `src/TGWST.Core`: small Windows security primitives shared by the GUI.
- `TGWST.sln`: authoritative solution for Debug and Release validation.

## Removed Surfaces

- Command shell and command registry.
- User-input output panes.
- Legacy network sidecars and broken DNS bridge integrations.
- Service companion and updater process.
- Local model assistant, model folder, feed updater, policy-management UI, installer staging artifacts.

## Active Data Sources

- IP Helper API for TCP/UDP connection snapshots.
- Network interfaces for bandwidth sampling.
- `netsh.exe` direct invocation for firewall profile status.
- Defender PowerShell cmdlets through direct `System32` PowerShell execution for read-only posture.
- WMI process and registry events for telemetry discovery.
- `FileSystemWatcher` for startup folder changes.
- Windows Event Log reader for high-signal findings.

## UX Rules

- GUI-only; no command input and no shell output.
- Monospace, dark, ASCII-style panels.
- Palette limited to cyan, red, orange, white, light gray, black, and deep navy.
- High-level dashboards first; raw details are reduced to actionable rows.
- Local paths and account names are not shown in dashboard rows.
