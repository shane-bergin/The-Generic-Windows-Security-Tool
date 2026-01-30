TGWST Architecture + UX Notes (for Claude Code)

Context
- We are editing from a bash shell (WSL-style), but the app is a Windows 11 Pro WPF application built with .NET 8.
- The repo includes Windows-specific code paths (PowerShell, CiTool, WMI, Defender cmdlets) and will ship with an installer.

UI Model (Terminal-first, GUI-backed)
- Single-screen WPF shell with:
  - Menu list (BIOS style)
  - Scrollback output
  - Command bar at the bottom
  - Optional attached "tmux-style" pane for live/progress output
- Keyboard-first interaction; no modal blocking dialogs.
- Acronym expansion is a single F2 toggle. Expanded acronyms render purple.

Keybindings
- Up/Down: move menu selection
- Enter: run selected menu item (when command line is empty) or execute typed command
- Left: go back one menu level (Alt+Left works too)
- Right: expand details for selected menu item (summary -> full)
- Ctrl+Up/Down: command history
- PageUp/PageDown: scroll active pane (attached pane if open; otherwise main output)
- Home/End: jump to top/bottom of active pane
- Ctrl+P: pause/resume attached pane updates
- Ctrl+W: close attached pane (press twice to confirm)
- F2: toggle acronym expansion
- F3: explain last output block
- F4: summarize output blocks
- F10: quit

Attached Pane (tmux-style)
- When a long-running action or live monitor starts, a secondary pane is attached under the main output.
- The pane can be paused for scrolling (Ctrl+P) and closed with confirmation (Ctrl+W twice).
- Status text (Live/Paused/Failed/etc.) is color-coded.

Menu Detail Expansion
- Right Arrow toggles detail levels on the selected menu entry:
  - Level 1: summary (what it does)
  - Level 2: full detail (changes, risks, rollback, prerequisites)
- Summary stays compact to keep the menu readable.

Network Monitoring (current implementation)
- Enhanced live monitor uses:
  - FlowCapturePipeline (ETW + IP Helper under the hood)
  - FlowAggregator for bandwidth totals and active flow rollups
  - EnrichmentService for process metadata and Geo
  - FlowRecordStore (SQLite) for historical stats
- Output includes per-process totals and top active flows with country/action columns.
- The monitor runs in the attached pane and supports pause + scroll.

Security Operations
- ASR, WDAC, Defender scan, compliance, uninstall/remnants are implemented as command handlers.
- Actions snapshot state before changes and support rollback where possible.
- WDAC dev-allow command generates a supplemental policy for developer workflows.

Build & Run
- Windows build (PowerShell):
  - dotnet build src/TGWST.App/TGWST.App.csproj -c Release
- Example run path after build:
  - src/TGWST.App/bin/Release/net8.0-windows/TGWST.exe
  - Note: launch with .\TGWST.exe from PowerShell.

Files of interest
- src/TGWST.App/Views/ShellView.xaml (terminal shell UI)
- src/TGWST.App/Views/ShellView.xaml.cs (key handling, scrolling, pane controls)
- src/TGWST.App/ViewModels/ShellViewModel.cs (menu, output, keyboard behaviors)
- src/TGWST.App/Shell/Commands/*.cs (commands)
- src/TGWST.Core/Network/* (network pipeline, storage, enrichment)
