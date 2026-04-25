# The Generic Windows Security Tool

TGWST is now a lean Windows 11 security awareness dashboard for .NET 8 and WPF. It is GUI-only, machine-agnostic, and focused on high-signal posture telemetry instead of command workflows or raw data dumps.

## Scope

- No command prompt, shell surface, service companion, updater process, or local model assistant.
- Machine-agnostic storage through Windows known folders such as `%LOCALAPPDATA%` and `%PROGRAMDATA%`.

## Dashboards
<img width="1299" height="847" alt="image" src="https://github.com/user-attachments/assets/0156f6e9-013c-4704-8567-91e5a8482296" />

### Dashboard

- Security Score from 0 to 100.
- Threat Level: Normal, Elevated, or Critical.
- System Integrity percentage.
- Network Exposure level.
- Last Defender full scan time when available.
- Active Threats count based on risky network and telemetry signals.

### Network

- Active TCP/UDP discovery through IP Helper API polling.
- Inbound exposure and outbound connection counts.
- Risky connection scoring by listener exposure, public remotes, sensitive ports, and unresolved processes.
- Interface bandwidth sampling.
- Firewall profile status.

### Telemetry

- Active process-start discovery through WMI.
- Startup registry key change discovery when WMI registry events are available.
- Startup folder file change discovery.
- Colored ASCII event feed and a compact risk timeline.

### Tools

- Quick Integrity Scan using `sfc.exe /verifyonly`.
- Startup Audit for Run key entries with security impact flags.
- Junk Analyzer and safe-only cleanup.
- Event Log 24h high-signal review.

### Logs

- Persistent local GUI event log.
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

Some telemetry sources may report degraded status without elevation. The app does not weaken controls for convenience; it continues read-only discovery and reports protected checks as degraded.
