# The Generic Windows Security Tool (TGWST)

![TGWST](https://img.shields.io/badge/TGWST-Windows%2011%20Security%20Tool-blue?logo=windows&logoColor=white&style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20Pro%20x64-0078D4?logo=windows&style=flat-square)
![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=.net&style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

A **Windows 11** desktop application for host hardening, compliance checking, drift detection, BitLocker management, WDAC policy control, event-log inspection, and deep file scanning with packaged **YARA / Sigma / ClamAV** engines.

Built in **.NET 8 (WPF)** with clean MVVM bindings, selection-driven UX, and a fully **offline-capable MSI installer**.  
Most operations require **Administrator privileges**.

---

## Features Overview

### Hardening (ASR / Defender / Firewall / Fortress Mode)
- Microsoft Defender settings (real-time protection, network protection, CFA, etc.)
- Attack Surface Reduction (ASR) rule profiles
- **One-click Fortress Mode** – blocks all inbound connections, allows outbound
- Restoration to earliest captured baseline (`%ProgramData%\TGWST`)

---

### WDAC – Windows Defender Application Control
Manage WDAC policies without touching XML/CIP files manually.

| Capability                              | Details |
|-----------------------------------------|---------|
| Policy sources                          | `%ProgramData%\TGWST\WDAC` (Balanced, Aggressive, Audit, Revert) <br> System locations (`C:\Windows\schemas\CodeIntegrity`, `C:\Windows\System32\CodeIntegrity`) |
| Actions                                 | Apply / Remove selected policy |
| Optional UMCI Enforcement Mode          | Yes |
| Real-time status indicator              | Shows active policy |

---

### BitLocker Management
Central control for OS, fixed, and removable drives.

- Auto-discovered drives with status labels (e.g., `C: (OS, Encrypted)`, `D: (Fixed, Not encrypted)`)
- Enable encryption per drive type
- Suspend / resume protectors
- Generate & export recovery keys
- PIN / password input fields
- All actions gated by selections and elevation

---

### Compliance – Registry Baseline Evaluation
Evaluate system state against formal security baselines.

- Baseline dropdown populated from `%ProgramData%\TGWST\Baselines`
  - `CIS_L1_Windows11.csv`
  - `CIS_L2_Windows11.csv`
  - `CISA_Recommended.csv`
  - `TGWST_Balanced.csv`
- “Browse…” for additional JSON/CSV baselines
- Results table: **Registry Path | Expected | Actual | Compliant**
- Summary: **e.g., Compliant 142/198**
- Selected baseline auto-propagates to Drift Detection

---

### Drift Detection – Continuous Baseline Monitoring
- Baseline auto-filled from last Compliance selection
- Interval selector: **30s | 60s | 300s | 900s**
- Start / Stop monitoring
- Output example:  
  `Drift check: 146/198 compliant @ 14:32:10`

---

### Event Log Analysis
Lightweight endpoint detection without a SIEM.

- Predefined lookbacks: **1h | 6h | 24h | 72h | 7 days**
- Detects:
  - Failed logons  
  - Process creation anomalies  
  - Service installations  
  - Script block activity  
- Bound DataGrid presents timestamp, event source, rule category, message, etc.

---

### Scan – YARA, Sigma, and Packaged ClamAV
Multi-engine scanning pipeline for file systems and suspicious directories.

#### ClamAV Integration (Packaged)
- MSI bundles portable **ClamAV 1.4.1 win-x64**
- Installed to:
  - `C:\ProgramData\TGWST\ClamAV\bin`
  - `C:\ProgramData\TGWST\ClamAV\db`
- Signatures included (`main.cvd`, `daily.cvd`, `bytecode.cvd`) or pulled fresh on first run
- Auto-refresh if signatures are > 24 hours old
- Toggle: **Use ClamAV Deep Scan**

#### YARA & Sigma
- Integrated **dnYara** engine
- Rule aggregation from ProgramData feed paths
- Sigma rules used for Event Log behavior correlation
- Scan tab shows progress and multi-engine hit reporting

---

## Installer & Packaging

### MSI Installer
TGWST can be built into a single **offline-capable MSI** containing:
- Application binaries  
- Packaged ClamAV payload (bin + signature DB)  
- ProgramData directory structure  

Generate the MSI:

```powershell
powershell -ExecutionPolicy Bypass -File installer\build-msi.ps1
