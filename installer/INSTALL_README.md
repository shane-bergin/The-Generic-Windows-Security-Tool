# The Generic Windows Security Tool (TGWST)

![TGWST](https://img.shields.io/badge/TGWST-Windows%2011%20Security%20Tool-blue?logo=windows&logoColor=white&style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20Pro%20x64-0078D4?logo=windows&style=flat-square)
![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=.net&style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

A **Windows 11** desktop application for host hardening, compliance checking, drift detection, BitLocker management, WDAC policy control, event-log inspection, and deep file scanning with **YARA / Sigma / LLM-powered script analysis** engines.

Built in **.NET 8 (WPF)** with clean MVVM bindings, selection-driven UX, and a fully **offline-capable MSI installer**.  
Most operations require **Administrator privileges**.

---

## Features Overview

### Hardening (ASR / Defender / Firewall / Fortress Mode)
- Microsoft Defender settings (real-time protection, network protection, CFA, etc.)
- Attack Surface Reduction (ASR) rule profiles
- **One-click Fortress Mode** - blocks all inbound connections, allows outbound
- Restoration to earliest captured baseline (`%ProgramData%\TGWST`)

---

### WDAC - Windows Defender Application Control
Manage shipped and imported WDAC policies from `%ProgramData%\TGWST\WDAC` (seeded from `%ProgramFiles%\TGWST\WDAC` on first run).

**Shipped policy set** (`src/TGWST.App/Assets/WDAC/wdac-shipped-policies.json`):
- `WDAC_Audit_Base.xml` - FriendlyName: *TGWST WDAC Audit Base*, v10.0.3.0, Audit, UMCI on.
- `WDAC_Enforced_Enterprise.xml` - *TGWST WDAC Enforced - Enterprise*, v10.0.3.0, Enforced, UMCI on.
- `WDAC_Enforced_Microsoft_Only.xml` - *TGWST WDAC Enforced - Microsoft Only*, v10.0.3.0, Enforced, UMCI on.
- `WDAC_Enforced_MS_And_Store.xml` - *TGWST WDAC Enforced - Microsoft + Store*, v10.0.3.0, Enforced, UMCI on.
- `WDAC_Enforced_With_Recommended_Driver_Block_Rules.xml` - *Microsoft Recommended Driver Block Rules (Enforced)*, v10.0.27805.0, supplemental driver block list (UMCI off).

**Capabilities**
- Import/export XML or CIP with collision-safe naming; XML->CIP compile with stdout/stderr capture and deterministic output alongside the XML.
- Enumerate XML/CIP pairs as single entries with source metadata (shipped/imported/generated) and duplicate/collision detection.
- Apply with UMCI toggle, track applied PolicyIDs under ProgramData, and remove only TGWST-tracked policies.
- Structured action log (import/compile/apply/remove) surfaced in the Hardening tab.

**Safe rollout (recommended)**
1. Apply `WDAC_Audit_Base.xml` in audit mode to observe impact.
2. Review event logs, tune as needed, then shift to an enforced baseline (Enterprise, Microsoft-only, or Microsoft+Store).
3. Layer the Microsoft recommended driver block policy as a supplemental policy.
4. Use Export to archive the applied CIP before broad deployment.

### BitLocker Management
Central control for OS, fixed, and removable drives.

- Auto-discovered drives with status labels (e.g., `C: (OS, Encrypted)`, `D: (Fixed, Not encrypted)`)
- Enable encryption per drive type
- Suspend / resume protectors
- Generate & export recovery keys
- PIN / password input fields
- All actions gated by selections and elevation

---

### Compliance â€“ Registry Baseline Evaluation
Evaluate system state against formal security baselines.

- Baseline dropdown populated from `%ProgramData%\TGWST\Baselines`
  - `CIS_L1_Windows11.csv`
  - `CIS_L2_Windows11.csv`
  - `CISA_Recommended.csv`
  - `TGWST_Balanced.csv`
- â€œBrowseâ€¦â€ for additional JSON/CSV baselines
- Results table: **Registry Path | Expected | Actual | Compliant**
- Summary: **e.g., Compliant 142/198**
- Selected baseline auto-propagates to Drift Detection

---

### Drift Detection â€“ Continuous Baseline Monitoring
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
- Bound DataGrid presents timestamp, event source, rule category, message, etc.

---

### Scan - YARA, Sigma, and LLM Script Analysis
Multi-engine scanning pipeline for file systems and suspicious directories.

#### LLM-Powered Script Analysis (API)
- Uses API-based LLMs (OpenAI, xAI, or Gemini) configured in **LLM Settings**
- Analyze script files (.ps1, .bat, .js, .vbs) for malicious patterns
- No local model download required; provide your API key and model name
- Defaults: `gpt-4o-mini` (OpenAI), `grok-beta` (xAI), `gemini-1.5-flash` (Gemini)
- Toggle: **Use LLM Script Analysis**
- Returns classification: Benign / Suspicious / Malicious

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
- ProgramData directory structure  

Generate the MSI:

```powershell
powershell -ExecutionPolicy Bypass -File installer\build-msi.ps1

