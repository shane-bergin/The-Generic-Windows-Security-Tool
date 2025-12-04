# TGWST IOC/YARA Feeds

TGWST can consume offline-generated detection intelligence (no bundled Ghidra). Drop files here:

- YARA rules: `C:\ProgramData\TGWST\Feeds\Yara\*.yar`
- IOC bundles (JSON): `C:\ProgramData\TGWST\Feeds\Iocs\*.json`

The app auto-creates these directories and reloads feeds via the “Reload Feeds” button in the Scan tab.

## IOC JSON schema (`IocBundle`)

```json
{
  "family": "Example.Family",
  "source": "Ghidra export",
  "sampleHash": "SHA256",
  "mutexes": ["Global\\mut1", "Global\\mut2"],
  "registryKeys": ["HKCU\\Software\\Example"],
  "filenames": ["evil.dll", "svc.exe"],
  "domains": ["bad.example.com"],
  "ips": ["10.0.0.5"],
  "createdUtc": "2025-01-01T12:00:00Z"
}
```

Arrays and fields are optional; missing fields are tolerated. Files may contain a single object or an array of objects.

## YARA rules

- Standard `.yar` syntax. One or more files placed under `C:\ProgramData\TGWST\Feeds\Yara\`.
- Rules from feeds are tagged in results as `Source: External Feed`.

## Example workflow (Ghidra → TGWST)

1. In Ghidra, export signatures and IoCs:
   - YARA rules: save as `.yar`.
   - IoCs: export JSON matching the schema above.
2. Copy files to:
   - `C:\ProgramData\TGWST\Feeds\Yara\your_rules.yar`
   - `C:\ProgramData\TGWST\Feeds\Iocs\bundle.json`
3. In TGWST Scan tab, click **Reload Feeds**. The counts update and YARA matches from feed rules are tagged as external.
