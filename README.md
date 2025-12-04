# The Generic Windows Security Tool (TGWST)


# Tab Summary

## Hardening

Applies Defender and ASR profiles. **Aggressive** enables CFA + HVCI. **Audit** logs ASR activity without blocking. **Revert** restores the saved baseline.

## Scan

YARA‑based scanning using embedded rules. **Quick** scans ~500 files; **Deep** scans ~5000.

## Uninstall

Runs standard uninstallers and removes leftover files/registry entries. Similar in concept to Revo Uninstaller.

## Network

Shows listening ports, allows port‑level blocking, and provides Fortress Mode, firewall reset, and threat blocklist controls.

<img width="974" height="663" alt="image" src="https://github.com/user-attachments/assets/78421247-3c00-4d67-87a5-d9e97fd734a4" />

<img width="964" height="655" alt="image" src="https://github.com/user-attachments/assets/7a397daf-23ef-4615-bb2a-2c440a3550da" />

<img width="965" height="659" alt="image" src="https://github.com/user-attachments/assets/3d2269ae-59fe-4033-98db-ce78556a1d09" />

<img width="968" height="658" alt="image" src="https://github.com/user-attachments/assets/5044c94a-e189-491c-8c27-3f9626c5ebbc" />



---

# What It Is

A Windows desktop application (WPF) with four tabs: **Hardening**, **Uninstall**, **Scan**, and **Network**. The application *requires Administrator rights* and will prompt for elevation on launch. Without elevation, it will close.

---

# Hardening

Applies one of four Microsoft Defender / ASR profiles and logs all changes. Profiles follow Microsoft’s standard set of 19 ASR rules.

## Profiles

### Balanced

* Defender realtime protection ON
* Network Protection ON
* ASR: all 19 ASR rules Enabled

### Aggressive

* All Balanced settings
* HVCI / Credential Guard configuration (reboot required)
* ASR: Enabled

### Audit

* Same baseline as Balanced
* ASR rules set to AuditMode (logged, not blocked)
* Displays reduced‑protection warning

### Revert

* Restores Defender/ASR settings from baseline:
  `C:/ProgramData/TGWST/MpPoliciesBaseline.json`

## Notes

* Tamper Protection cannot be modified by the app. To edit: Start → Windows Security → Virus & threat protection → Manage ransomware protection → Tamper Protection.
* Logs show Defender verification results (Realtime, Network Protection, CFA).
* Group Policy and enterprise security controls may override settings; the tool logs what Windows reports.

---

# Scan

Two YARA‑only scan modes. 

## Scan Types

### Quick (YARA)

* Scans Desktop, Documents, and LocalAppData
* ~500 executable/script files

### Deep (YARA)

* Scans all fixed drives
* ~5000 executable/script files

## What YARA Is

YARA is an open‑source malware detection engine maintained by the VirusTotal/Google security team with community contributors. It identifies files based on pattern‑matching rules. YARA detects only; it does not clean, remove, or quarantine. The app uses the embedded `Rules.yar` file.

## UI Behavior

* Progress bar indicates scan progress
* Log window prints scanned items and matches
* Results grid shows: Path, Engine, Reason

---

# Uninstall

Lists installed applications, runs their uninstallers, and removes file/registry leftovers.

## Behavior

1. Enumerates installed applications
2. Runs the selected app’s uninstaller
3. Scans for leftover files, folders, and registry keys
4. Allows removal of detected leftovers
5. Displays counts and status messages

---

# Network

Displays active listening ports and provides firewall‑hardening actions.

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

*Enables Windows Defender Firewall across all profiles

*Sets policy to **block all inbound** and **allow all outbound**

Quickly reduces attack surface by denying all unsolicited inbound connections except built‑in Windows rules

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

```bash
dotnet restore TGWST.sln
dotnet publish src/TGWST.App/TGWST.App.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeAllContentForSelfExtract=true /p:PublishTrimmed=false -o publish

