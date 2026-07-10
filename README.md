# The Generic Windows Security Tool

TGWST is a lean Windows security awareness dashboard for .NET 8 and WPF with a narrow set of confirmation-gated, verified response actions. It is machine-agnostic and focused on high-signal posture telemetry instead of raw data dumps.

## Scope

- Pure WPF desktop GUI with a dark ASCII/cyber dashboard aesthetic.
- Monospace UI, black/deep-navy background, and a strict cyan/red/orange/white/light-gray palette.
- No embedded command prompt, service companion, updater process, or local model assistant. CLI flags are reserved for packaged TGWST response workflows launched by the GUI or an administrator.
- Machine-agnostic storage through Windows known folders such as `%LOCALAPPDATA%` and `%PROGRAMDATA%`.
- Tray icon reflects current threat level with cyan, orange, or red status.

## Dashboards

### Dashboard

- Security Score from 0 to 100.
- Threat Level: Normal, Elevated, or Critical.
- Network Exposure level.
- Active Threats count based on risky network and telemetry signals.
- Defender and firewall states that map to built-in hardening actions.
- Targeted Defender update/quick-scan, firewall enable/default-inbound-block, SMBv1 disable, and selected-endpoint containment actions.
- Broad, destructive, or experimental workflows remain visibly staged and disabled until they have a trusted elevation boundary, effective-state verification, and recovery support.
- Actionable display policy: dashboard tabs show information TGWST can help change, halt, configure, block, clean, or audit.

### Network

- Active TCP/UDP discovery through IP Helper API polling.
- Inbound exposure and firewall posture.
- Risky connection scoring by listener exposure, public remotes, sensitive ports, and unresolved processes.
- Visible network grids are limited to inbound control targets and block/kill candidates.
- Optional hardening for SMB/NetBIOS, mDNS/LLMNR, SSDP/WSD, qWave, CDPSvc, USB-over-IP, IKE/IPsec, LLMNR policy, NetBIOS over TCP/IP, and firewall packet logging.

### Staged Windows Scripts

The scripts under `scripts/windows11` are reviewable development artifacts. The GUI does **not** elevate or execute these mutable files in the current build. They must not be treated as production remediation until TGWST ships them through a signed or embedded trust boundary and validates per-control results and rollback.

- `scripts/windows11/Invoke-TGWST-NetworkSurfaceHardening.ps1` applies the GUI network surface hardening flow. It can disrupt file sharing, network discovery, casting, Remote Assistance, VPN/IPsec, USB-over-IP, and device pairing workflows.
- `scripts/windows11/Invoke-TGWST-Windows11BarebonesLockdown.ps1` applies an emergency Windows 11 lockdown profile: saves rollback snapshots, disables non-core inbound allow rules, blocks common remote-service ports, disables convenience/remote/discovery services, and terminates user-space anomaly process candidates.
- `scripts/windows11/Get-TGWST-InboundSurfaceAudit.ps1` generates a JSON audit of watched inbound ports, WFP Security events, network logons, file-share/SMB evidence, firewall logging status, and enabled inbound allow rules.
- `scripts/windows11/Get-TGWST-WindowsCveExposure.ps1` retrieves MSRC/CISA data for the May 1, 2026 through June 22, 2026 Windows CVE window and checks local update, Defender, BitLocker, WinRE, and domain-controller posture.
- `scripts/windows11/Invoke-TGWST-WindowsCveSafeguards.ps1` refreshes and hardens Defender, requests ASR block rules, starts Windows Update discovery, and enforces the firewall baseline without modifying WinRE recovery images.
- `scripts/windows11/Test-TGWST-EicarDefender.ps1` runs an opt-in EICAR antivirus readiness test only after Defender meets the June 2026 engine/platform thresholds, then verifies detection or remediation, cleans up, and writes a JSON report.

### Telemetry

- Active process-start discovery through WMI.
- Suspended process start detection with read-only thread inspection.
- Startup registry key change discovery when WMI registry events are available.
- Startup folder file change discovery.
- Warning/critical telemetry queue for response decisions.

### Tools

- Quick Integrity Scan using `sfc.exe /verifyonly`.
- Startup Audit for Run key entries with security impact flags.
- Registry, `%TEMP%`, `%APPDATA%`, and `%LOCALAPPDATA%` residue analyzer with safe-only cleanup.
- Event Log 24h high-signal review.

### Logs

- Persistent local GUI event log.
- Read-only colored ASCII feed with severity filtering.
- No user input surface.

## Build

```powershell
dotnet build TGWST.sln
dotnet build TGWST.sln -c Release
```

## Run

```powershell
dotnet run --project src\TGWST.App\TGWST.App.csproj
```

GUI is the interactive dashboard. The supported CLI surface is intentionally minimal:

```powershell
TGWST.exe --help
TGWST.exe --version
```

Safeguards, WDAC, BitLocker, reparse, export, and quick-posture CLI commands return `UNAVAILABLE` without changing security state until their implementations are production-ready.

## Windows Safeguards Research Scaffold

The repository contains experimental code and scripts exploring Defender ancestry, reparse points, BitLocker/WinRE, WDAC, and update posture. Several paths are advisory or incomplete; they are not represented as enforced controls in the GUI or supported CLI.

Before these experiments can become automatic controls they require signed baseline data, a secured elevated broker, explicit compatibility preview, typed applied/partial/failed results, independent verification, and tested recovery. Patching and the authoritative Windows management plane remain mandatory.

See operational briefing for full mapping and CONOPS. Patching remains mandatory.

Some telemetry sources may report degraded status without elevation. TGWST reports missing evidence as `UNKNOWN`/`DEGRADED`, not as proof that a control is disabled or healthy.
