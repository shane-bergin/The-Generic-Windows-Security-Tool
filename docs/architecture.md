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
- Structured `Get-NetFirewallProfile -PolicyStore ActiveStore` JSON for firewall profile status.
- Defender PowerShell cmdlets through direct `System32` PowerShell execution for read-only posture.
- WMI process and registry events for telemetry discovery (Win32_ProcessStartTrace).
- Read-only suspended-thread inspection for recently started processes.
- `FileSystemWatcher` for startup folder changes.
- Windows Event Log reader for high-signal findings.
- Registry Run keys and user temp/AppData locations for residue analysis.
- Fixed, targeted elevated actions for Defender update/scan, firewall enable/default inbound block, SMBv1 disable, and selected firewall containment.
- Windows safeguard scripts and WDAC/BitLocker/reparse experiments remain staged development artifacts and are not executable through the supported GUI/CLI surface.

## Elevated Response Paths

Only narrow actions with fixed command construction and post-change checks are enabled. Mutable packaged scripts, broad ASR/network profiles, WDAC staging, and destructive lockdown are gated off pending a signed/embedded trust boundary and recovery contract.

- `DashboardActionService` owns fixed Defender, firewall, and SMBv1 actions and launches absolute `System32` binaries with UAC confirmation.
- `NetworkResponseService` revalidates PID start time and executable path before a process-scoped action; firewall containment uses one elevated transaction, unique rule IDs, verification, and partial-failure cleanup.
- The scripts under `scripts/windows11` are source artifacts for review and future broker integration. Direct packaged-script elevation throws `NotSupportedException` in this build.

## UX Rules

- GUI-only; no command input and no shell output.
- Monospace, dark, ASCII-style panels.
- Palette is black/near-black, white/gray, one muted cyan emphasis hue, and one amber warning hue.
- High-level dashboards first; raw details are reduced to actionable rows.
- Local paths and account names are not shown in dashboard rows.
- Cleanup is safe-only by default, revalidates registry values, enforces canonical root containment, and refuses reparse-point trees.
- Display surfaces should be action-scoped: show rows that map to a TGWST action such as configure, halt, block, clean, quarantine-by-lockdown, audit, or open the native Windows control surface.
