# The Generic Windows Security Tool (TGWST)

![TGWST](https://img.shields.io/badge/TGWST-Windows%2011%20Security%20Tool-blue?logo=windows&logoColor=white&style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%2011%20Pro%20x64-0078D4?logo=windows&style=flat-square)
![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=.net&style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

A Windows 11 desktop application for host hardening, compliance checking, drift monitoring, BitLocker management, WDAC policy control, event-log inspection, and multi-engine file scanning that combines **YARA**, **Sigma**, and **LLM-powered script analysis**.

Built on **.NET 8 (WPF)** with MVVM bindings, selection-aware controls, and a fully **offline-capable MSI installer**. Most workflows require **Administrator privileges**.

---

## Features Overview

### Hardening (ASR / Defender / Firewall / Fortress Mode)
- Configure Microsoft Defender including real-time protection, network protection, Controlled Folder Access, and other Defender settings.
- Use curated Attack Surface Reduction (ASR) rule profiles that can be toggled per profile.
- **One-click Fortress Mode** blocks inbound traffic while leaving outbound untouched.
- Restore Defender and firewall settings to the earliest captured baseline stored at `%ProgramData%\TGWST`.

### WDAC – Windows Defender Application Control
Manage shipped and imported WDAC policies from `%ProgramData%\TGWST\WDAC` (seeded from `%ProgramFiles%\TGWST\WDAC` on first run).

**Shipped policy set** (`src/TGWST.App/Assets/WDAC/wdac-shipped-policies.json`):
- `WDAC_Audit_Base.xml` – *TGWST WDAC Audit Base*, v10.0.3.0, Audit mode with UMCI enabled.
- `WDAC_Enforced_Enterprise.xml` – *TGWST WDAC Enforced – Enterprise*, v10.0.3.0, Enforced mode with UMCI enabled.
- `WDAC_Enforced_Microsoft_Only.xml` – *TGWST WDAC Enforced – Microsoft Only*, v10.0.3.0, Enforced with UMCI enabled.
- `WDAC_Enforced_MS_And_Store.xml` – *TGWST WDAC Enforced – Microsoft + Store*, v10.0.3.0, Enforced with UMCI enabled.
- `WDAC_Enforced_With_Recommended_Driver_Block_Rules.xml` – *Microsoft Recommended Driver Block Rules (Enforced)*, v10.0.27805.0, supplemental driver block list (UMCI off).

**Capabilities**
- Import/export XML or CIP with collision-safe names and deterministic XML→CIP compilation that captures stdout/stderr.
- Treat XML/CIP pairs as single catalog entries, exposing the source (shipped/imported/generated) and flagging duplicates/collisions.
- Apply policies with optional UMCI, track the applied PolicyIDs under ProgramData, and remove only TGWST-tracked policies.
- Action log (import, compile, apply, remove) is visible from the Hardening tab.

**Safe rollout (recommended)**
1. Apply `WDAC_Audit_Base.xml` in audit mode to detect compatibility issues.
2. Review event logs, address findings, and move to an enforced profile (Enterprise, Microsoft Only, or Microsoft + Store).
3. Layer the recommended driver block policy as a supplemental policy.
4. Export the resulting CIP before deploying widely.

### BitLocker Management
Central control for OS, fixed, and removable drives.

- Auto-discovers drives with captions such as `C: (OS, Encrypted)` or `D: (Fixed, Not encrypted)`.
- Enable encryption per drive type and manage TPM/PIN protectors.
- Suspend/resume protectors and generate/export recovery keys from the UI.
- PIN and password input fields are shown on demand; every action requires an explicit selection and elevated context.

### Compliance – Registry Baseline Evaluation
Evaluate system configuration against published baselines.

- Baseline dropdown populated from `%ProgramData%\TGWST\Baselines`.
  - `CIS_L1_Windows11.csv`
  - `CIS_L2_Windows11.csv`
  - `CISA_Recommended.csv`
  - `TGWST_Balanced.csv`
- “Browse…” for additional JSON or CSV baselines.
- Results table columns: **Registry Path | Expected | Actual | Compliant**.
- Summary sentence like **“Compliant 142/198”**.
- Selected baseline automatically propagates to Drift Detection.

### Drift Detection – Continuous Baseline Monitoring
- Baseline is pre-filled from the most recent Compliance selection.
- Interval selector options: **30s | 60s | 300s | 900s**.
- Start/stop monitoring buttons and live status updates.
- Sample output: `Drift check: 146/198 compliant @ 14:32:10`.

### Event Log Analysis
Lightweight endpoint anomaly detection without a SIEM.

- Lookback presets: **1h | 6h | 24h | 72h | 7 days**.
- Rules detect failed logons, suspicious process creations, and service installations.
- Results list shows timestamp, source, rule category, and message for each finding.

### Scan – YARA, Sigma, and LLM Script Analysis
Multi-engine scanning pipeline for file systems and high-risk directories.

#### LLM-Powered Script Analysis (API)
- Uses API-based LLMs (OpenAI, xAI, Gemini) configured in the **LLM Settings** window.
- Analyzes script files (.ps1, .bat, .js, .vbs) for malicious intent.
- No large local model download required; supply your API key and model name.
- Defaults: `gpt-4o-mini` (OpenAI), `grok-beta` (xAI), `gemini-1.5-flash` (Gemini).
- Toggle `Use LLM Script Analysis` to include or skip this engine.
- Reports a classification (Benign / Suspicious / Malicious) per script.

#### YARA & Sigma
- Ships with an embedded **dnYara** engine.
- Aggregates rules from the ProgramData feed paths.
- Sigma rules focus on event-log behavior correlation.
- Scan tab reports progress, hit counts, and hits per engine.

---

## Installer & Packaging

### MSI Installer
TGWST can be packaged into a single **offline-capable MSI** that contains:
- Application binaries.
- The `%ProgramData%\TGWST` directory structure (feeds, baselines, cache).

Generate the MSI with:

```powershell
powershell -ExecutionPolicy Bypass -File installer\build-msi.ps1
```
