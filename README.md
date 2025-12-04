# The Generic Windows Security Tool (TGWST)


# Tab Summary

## Hardening

Applies Defender and ASR profiles. **Aggressive** enables CFA + HVCI. **Audit** logs ASR activity without blocking. **Revert** restores the saved baseline.

## Scan

YARA-based scanning using embedded rules. **Quick** scans ~500 files; **Deep** scans ~5000.

## Uninstall

Lists installed applications, runs their uninstallers, and removes file/registry leftovers.

## Behavior

1. Enumerates installed applications
2. Runs the selected app's uninstaller
3. Scans for leftover files, folders, and registry keys
4. Allows removal of detected leftovers
5. Displays counts and status messages

---

# Network

Displays active listening ports and provides firewall-hardening actions.

## Grid Columns

* Protocol
* Address
* Port
* PID
* Process
* Service

## Actions

### Block

Adds an inbound Windows Firewall rule blocking the selected port/protocol.

### Fortress Mode

* Enables Windows Defender Firewall across all profiles
* Sets policy to **block all inbound** and **allow all outbound**

Quickly reduces attack surface by denying all unsolicited inbound connections except built-in Windows rules.

### Reset Firewall

Restores default Windows Firewall settings using:

```
netsh advfirewall reset
```

### Apply Threat Blocklists

Adds outbound block rules sourced from:

* Feodo Tracker (aggressive feed)
* FireHOL Level 1

Often results in hundreds of outbound blocks.

### Remove Threat Rules

Removes all firewall rules previously created by the blocklist feature.

---

# Build & Install

```bash
dotnet restore TGWST.sln
dotnet publish src/TGWST.App/TGWST.App.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeAllContentForSelfExtract=true /p:PublishTrimmed=false -o installer/publish
powershell -ExecutionPolicy Bypass -File installer/install-wizard.ps1
```

- Optional EXE wrapper (ps2exe): `powershell -ExecutionPolicy Bypass -File installer/ps2exe-wrapper.ps1 -OutputExe installer/TGWST-Installer.exe` (ship with `installer/publish` payload).
- MSI build (WiX Toolset 3.11+ required): `powershell -ExecutionPolicy Bypass -File installer/build-msi.ps1` to generate `installer/TGWST.Setup.msi` from the publish output. Distribute the MSI as the single offline installer.

### ClamAV (packaged)
- TGWST ships a portable ClamAV instance under `C:\ProgramData\TGWST\ClamAV\` (bin + db) with the MSI/publish payload. No global PATH changes or services are installed.
- In the Scan tab, enable “Use ClamAV deep scan” to include a ClamAV pass. On first enable (or when signatures are older than 24h) TGWST runs the bundled `freshclam.exe` to refresh the DB; offline failures are logged but won’t block the rest of the scan.
- Advanced override: set `CLAMAV_PATH` to a directory containing `clamscan.exe` (or place `clamscan.exe` on PATH). TGWST always prefers the bundled `C:\ProgramData\TGWST\ClamAV\bin\clamscan.exe` first, then `CLAMAV_PATH`, then PATH.
