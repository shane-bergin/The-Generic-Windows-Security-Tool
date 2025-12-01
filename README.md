TGWST – The Generic Windows Security Tool (v2.0)

Single-EXE fortress for Windows 11:

- ASR & Defender hardening (Balanced / Aggressive / Paranoid / Audit / Revert)
- Deep uninstaller with residual cleanup (filesystem + registry)
- YARA + Sigma + optional ClamAV scan triad
- Network fortress: inbound block, outbound allow, threat IP blocklists

## Build

```bash
dotnet restore TGWST.sln
dotnet publish src/TGWST.App/TGWST.App.csproj -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:IncludeAllContentForSelfExtract=true /p:PublishTrimmed=false -o publish