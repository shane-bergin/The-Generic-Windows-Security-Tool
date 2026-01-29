using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using TGWST.App.Shell;

namespace TGWST.App.ViewModels
{
    public sealed class ShellViewModel : ObservableObject
    {
        private const string DefaultStatus = "WDAC:Audit | UMCI:Enabled";

        public ObservableCollection<OutputBlock> Output { get; } = new();
        public ObservableCollection<MenuEntryViewModel> MenuEntries { get; } = new();

        private readonly CommandRegistry _registry;
        private readonly TaskOutputService _outputService;
        private readonly InsightService _insightService;
        private bool _acronymsExpanded;
        private int _menuIndex;
        private MenuNode? _menuRoot;
        private MenuNode? _currentMenu;
        private ProgressViewModel? _attachedPane;
        private CancellationTokenSource? _attachedPaneCts;
        private bool _attachedPaneCloseConfirm;

        private string _commandLine = string.Empty;
        public string CommandLine
        {
            get => _commandLine;
            set => SetProperty(ref _commandLine, value);
        }

        private string _promptPrefix = "tgwst > ";
        public string PromptPrefix
        {
            get => _promptPrefix;
            private set => SetProperty(ref _promptPrefix, value);
        }

        public string FooterHints => "F2:Acronyms • ↑/↓:Menu • →:Details • Ctrl+↑/↓:History • Ctrl+W:Pane • Enter:Run • ←:Back • F3:Explain • F4:Summary • F10:Quit";

        private string _breadcrumb = "Home";
        public string Breadcrumb
        {
            get => _breadcrumb;
            private set => SetProperty(ref _breadcrumb, value);
        }

        private string _breadcrumbPath = "home";
        public string BreadcrumbPath
        {
            get => _breadcrumbPath;
            private set => SetProperty(ref _breadcrumbPath, value);
        }

        public ProgressViewModel? AttachedPane
        {
            get => _attachedPane;
            private set
            {
                if (SetProperty(ref _attachedPane, value))
                {
                    OnPropertyChanged(nameof(IsAttachedPaneVisible));
                }
            }
        }

        public bool IsAttachedPaneVisible => _attachedPane != null;

        public bool IsAttachedPaneClosePromptVisible => _attachedPaneCloseConfirm;

        public string AttachedPaneClosePrompt => _attachedPaneCloseConfirm
            ? "Close pane? Press Ctrl+W again to confirm."
            : string.Empty;

        private readonly List<string> _history = new();
        private int _historyIndex = -1;

        public ShellViewModel(CommandRegistry registry, TaskOutputService outputService, InsightService insightService)
        {
            _registry = registry;
            _outputService = outputService;
            _insightService = insightService;
            UpdatePromptPrefix(IsAdministrator());
            WriteBanner();
            BuildMenu();
        }

        public async Task ExecuteAsync()
        {
            ClearAttachedPaneClosePrompt();

            var cmd = (CommandLine ?? string.Empty).Trim();
            if (cmd.Length == 0)
            {
                return;
            }

            if (TrySelectMenuByNumber(cmd))
            {
                CommandLine = string.Empty;
                await ExecuteSelectedMenuAsync();
                return;
            }

            _history.Add(cmd);
            _historyIndex = _history.Count;

            AddOutput($"Command: {cmd}\n");

            CommandLine = string.Empty;

            var handled = await _registry.TryExecuteAsync(cmd, this);
            if (!handled)
            {
                AddOutput($"[error] Unknown command: {cmd}\nType: help\n");
            }
        }

        public void HistoryUp()
        {
            if (_history.Count == 0)
            {
                return;
            }

            _historyIndex = Math.Max(0, _historyIndex - 1);
            CommandLine = _history[_historyIndex];
        }

        public void HistoryDown()
        {
            if (_history.Count == 0)
            {
                return;
            }

            _historyIndex = Math.Min(_history.Count, _historyIndex + 1);
            CommandLine = _historyIndex >= _history.Count ? string.Empty : _history[_historyIndex];
        }

        public void AddOutput(string text)
        {
            var dispatcher = Application.Current?.Dispatcher;
            var display = _acronymsExpanded ? AcronymExpander.Expand(text) : text;

            if (dispatcher?.CheckAccess() == true)
            {
                Output.Add(new OutputBlock(text, display, _acronymsExpanded));
                return;
            }

            dispatcher?.Invoke(() => Output.Add(new OutputBlock(text, display, _acronymsExpanded)));
        }

        public void ClearOutput()
        {
            var dispatcher = Application.Current?.Dispatcher;
            if (dispatcher?.CheckAccess() == true)
            {
                Output.Clear();
                return;
            }

            dispatcher?.Invoke(Output.Clear);
        }

        public void ToggleAcronyms()
        {
            SetAcronymMode(!_acronymsExpanded);
        }

        public async Task ExplainLastBlockAsync()
        {
            var last = Output.LastOrDefault();
            if (last == null)
            {
                AddOutput("[info] No output to explain.\n");
                return;
            }

            var progressVm = _outputService.CreateAndShow("Explain Last Block", _acronymsExpanded);
            progressVm.Append("Analyzing last block...\n");
            var result = await _insightService.ExplainAsync(last.RawText);
            progressVm.Append(result + "\n");
            progressVm.Status = "Completed";
        }

        public async Task SummarizeBlocksAsync()
        {
            if (Output.Count == 0)
            {
                AddOutput("[info] No output to summarize.\n");
                return;
            }

            var blocks = Output.TakeLast(6).Select(b => b.RawText).ToArray();
            var input = string.Join("\n---\n", blocks);
            var progressVm = _outputService.CreateAndShow("Summarize Output", _acronymsExpanded);
            progressVm.Append("Summarizing last output blocks...\n");
            var result = await _insightService.SummarizeAsync(input);
            progressVm.Append(result + "\n");
            progressVm.Status = "Completed";
        }

        public async Task ExecuteSelectedMenuAsync()
        {
            if (MenuEntries.Count == 0) return;
            ClearAttachedPaneClosePrompt();
            var entry = MenuEntries[_menuIndex];
            if (entry.IsBack)
            {
                NavigateBack();
                return;
            }
            if (entry.Node.HasChildren)
            {
                NavigateTo(entry.Node);
                return;
            }

            if (!string.IsNullOrWhiteSpace(entry.Node.Command))
            {
                CommandLine = entry.Node.Command;
                await ExecuteAsync();
            }
        }

        private void WriteBanner()
        {
            AddOutput("Type `help` for commands. See footer for keyboard shortcuts.\n");
        }

        private void BuildMenu()
        {
            _menuRoot = new MenuNode(
                "Home",
                children: new[]
                {
                    new MenuNode("Security", children: new[]
                    {
                        new MenuNode("Defender", children: new[]
                        {
                            new MenuNode("ASR", children: new[]
                            {
                                new MenuNode("Apply Balanced", "asr apply balanced", "Balanced ASR rules + Defender options",
                                    detail: null,
                                    richDetail: new DetailContent
                                    {
                                        Summary = "Apply balanced Windows Defender ASR rules with real-time protection",
                                        Changes = new[]
                                        {
                                            "Enable real-time monitoring",
                                            "Enable network protection",
                                            "Set 19 ASR rules to Block mode",
                                            "Create snapshot at %ProgramData%\\TGWST\\MpPoliciesBaseline.json"
                                        },
                                        Risks = new[]
                                        {
                                            "May block some unsigned scripts and macros",
                                            "Office automation workflows may be affected",
                                            "Requires Administrator privileges"
                                        },
                                        RollbackInfo = "Use 'asr apply revert' to restore previous snapshot"
                                    }),
                                new MenuNode("Apply Strict", "asr apply strict", "Aggressive ASR baseline",
                                    detail: null,
                                    richDetail: new DetailContent
                                    {
                                        Summary = "Apply aggressive ASR profile with Controlled Folder Access and HVCI",
                                        Changes = new[]
                                        {
                                            "All Balanced profile changes",
                                            "Enable Controlled Folder Access",
                                            "Enable Hypervisor-protected Code Integrity (HVCI)",
                                            "Enable Credential Guard"
                                        },
                                        Risks = new[]
                                        {
                                            "Controlled Folder Access may block legitimate apps from writing",
                                            "HVCI/Credential Guard require compatible hardware",
                                            "Requires reboot to fully apply",
                                            "May need to disable Tamper Protection first"
                                        },
                                        RollbackInfo = "Use 'asr apply revert' - HVCI/CG may require manual registry changes"
                                    }),
                                new MenuNode("Apply Audit", "asr apply audit", "Log ASR events only",
                                    detail: null,
                                    richDetail: new DetailContent
                                    {
                                        Summary = "Set all ASR rules to Audit mode - logs events without blocking",
                                        Changes = new[]
                                        {
                                            "Set all 19 ASR rules to AuditMode",
                                            "Enable real-time monitoring",
                                            "Enable network protection"
                                        },
                                        Risks = new[]
                                        {
                                            "No protection - only logging",
                                            "Event log volume may increase",
                                            "Review events before switching to Block mode"
                                        },
                                        RollbackInfo = "Use 'asr apply revert' or apply Balanced/Strict"
                                    }),
                                new MenuNode("Revert", "asr apply revert", "Restore ASR snapshot",
                                    detail: null,
                                    richDetail: new DetailContent
                                    {
                                        Summary = "Restore the most recent ASR snapshot captured before changes",
                                        Changes = new[]
                                        {
                                            "Restore ASR rules to previous state",
                                            "Restore Defender preferences to snapshot values"
                                        },
                                        Risks = new[]
                                        {
                                            "May reduce protection if previous state was less secure",
                                            "Requires snapshot to exist"
                                        },
                                        RollbackInfo = "Re-apply Balanced or Strict profile"
                                    })
                            }),
                            new MenuNode("Scans", children: new[]
                            {
                                new MenuNode("Quick Scan", "scan defender quick", "Start-MpScan quick scan",
                                    detail: null,
                                    richDetail: new DetailContent
                                    {
                                        Summary = "Run Windows Defender quick scan on common threat locations",
                                        Changes = new[]
                                        {
                                            "Scans running processes and startup locations",
                                            "Scans common malware directories"
                                        },
                                        Risks = new[]
                                        {
                                            "CPU usage during scan",
                                            "May quarantine detected threats automatically"
                                        },
                                        RollbackInfo = "Restore quarantined items from Defender history"
                                    }),
                                new MenuNode("Full Scan", "scan defender full", "Start-MpScan full scan",
                                    detail: null,
                                    richDetail: new DetailContent
                                    {
                                        Summary = "Run comprehensive Windows Defender scan on all drives",
                                        Changes = new[]
                                        {
                                            "Scans all files on all mounted drives",
                                            "Deep scan of archives and executables"
                                        },
                                        Risks = new[]
                                        {
                                            "High CPU and disk I/O for extended period",
                                            "Can take hours on large drives",
                                            "May quarantine detected threats"
                                        },
                                        RollbackInfo = "Restore quarantined items from Defender history"
                                    })
                            })
                        }),
                        new MenuNode("WDAC", children: new[]
                        {
                            new MenuNode("Status", "wdac status", "Show WDAC status + active policies",
                                detail: null,
                                richDetail: new DetailContent
                                {
                                    Summary = "Display current WDAC/DeviceGuard state and installed policies",
                                    Changes = new[] { "Read-only operation - no system changes" },
                                    Risks = new string[] { }
                                }),
                            new MenuNode("Audit Mode", "wdac apply audit", "Stage and apply WDAC audit policy",
                                detail: null,
                                richDetail: new DetailContent
                                {
                                    Summary = "Apply WDAC in audit mode - logs blocked apps without enforcing",
                                    Changes = new[]
                                    {
                                        "Deploy WDAC_Audit_Base.xml policy via CiTool",
                                        "Track policy in %ProgramData%\\TGWST\\WDAC\\wdac-applied.json",
                                        "Generate code integrity events (Event ID 3076, 3077)"
                                    },
                                    Risks = new[]
                                    {
                                        "Does NOT block applications - audit only",
                                        "Event log volume may increase significantly",
                                        "Policy persists across reboots"
                                    },
                                    RollbackInfo = "Use 'wdac remove' to remove the TGWST-applied policy"
                                }),
                            new MenuNode("Enforced Mode", "wdac apply enforce", "Stage and enforce WDAC policy",
                                detail: null,
                                richDetail: new DetailContent
                                {
                                    Summary = "Apply WDAC in enforced mode - blocks unsigned/untrusted applications",
                                    Changes = new[]
                                    {
                                        "Deploy WDAC_Enforced_Microsoft_Only.xml policy",
                                        "Enable User Mode Code Integrity (UMCI)",
                                        "Block execution of non-whitelisted executables"
                                    },
                                    Risks = new[]
                                    {
                                        "CRITICAL: May block legitimate applications",
                                        "Recovery may require boot media if TGWST is blocked",
                                        "Test in audit mode first",
                                        "Use 'wdac dev allow' to whitelist TGWST.exe before enforcing"
                                    },
                                    RollbackInfo = "Boot into recovery, use 'wdac remove' or CiTool",
                                    Prerequisites = "Recommended: Run 'wdac dev allow' first to whitelist this tool"
                                }),
                            new MenuNode("Dev Allow (this EXE)", "wdac dev allow", "Allow TGWST.exe via supplemental policy",
                                detail: null,
                                richDetail: new DetailContent
                                {
                                    Summary = "Create supplemental policy to whitelist TGWST.exe for development",
                                    Changes = new[]
                                    {
                                        "Generate hash-based supplemental WDAC policy",
                                        "Apply policy via CiTool"
                                    },
                                    Risks = new[]
                                    {
                                        "Only whitelists current build hash",
                                        "Must re-run after recompiling TGWST"
                                    },
                                    RollbackInfo = "Use 'wdac dev remove' to remove the supplemental policy"
                                }),
                            new MenuNode("Dev Allow Remove", "wdac dev remove", "Remove last dev allow policy",
                                "Removes the supplemental dev-allow policy created by TGWST."),
                            new MenuNode("Revert", "wdac revert", "Revert to last WDAC snapshot",
                                "Re-applies the last WDAC policy snapshot captured by TGWST."),
                            new MenuNode("Remove Policy", "wdac remove", "Remove TGWST-applied policy",
                                detail: null,
                                richDetail: new DetailContent
                                {
                                    Summary = "Remove the most recent TGWST-applied WDAC policy",
                                    Changes = new[]
                                    {
                                        "Remove policy via CiTool",
                                        "Update tracking in wdac-applied.json"
                                    },
                                    Risks = new[]
                                    {
                                        "System may be less protected after removal",
                                        "Does not remove system policies (only TGWST-applied)"
                                    },
                                    RollbackInfo = "Re-apply audit or enforce mode"
                                })
                        })
                    }),
                    new MenuNode("Network", children: new[]
                    {
                        new MenuNode("Live Monitor", "network live", "Real-time TCP/UDP connections",
                            detail: null,
                            richDetail: new DetailContent
                            {
                                Summary = "Open live pane showing active TCP/UDP connections with DNS resolution",
                                Changes = new[] { "Read-only monitoring - no system changes" },
                                Risks = new string[] { },
                                RollbackInfo = "Press Ctrl+W to close the pane"
                            }),
                        new MenuNode("Baseline", "network baseline", "Firewall + listening ports summary",
                            detail: null,
                            richDetail: new DetailContent
                            {
                                Summary = "Capture snapshot of firewall profile state and listening ports",
                                Changes = new[] { "Read-only snapshot - no system changes" },
                                Risks = new string[] { }
                            }),
                        new MenuNode("Signature Check", "scan sdk sigcheck", "Verify signatures on a target path",
                            "Uses signtool if available; otherwise falls back to Authenticode checks.")
                    }),
                    new MenuNode("Compliance", children: new[]
                    {
                        new MenuNode("Snapshot", "compliance snapshot", "Capture compliance drift snapshot",
                            detail: null,
                            richDetail: new DetailContent
                            {
                                Summary = "Compare system state against imported baseline",
                                Changes = new[]
                                {
                                    "Read registry values specified in baseline",
                                    "Compare current values to expected values",
                                    "Generate compliance report"
                                },
                                Risks = new[]
                                {
                                    "Read-only operation - no system changes",
                                    "May take time on large baselines"
                                }
                            })
                    }),
                    new MenuNode("Uninstall", children: new[]
                    {
                        new MenuNode("Uninstall + Remnants", "uninstall remnants", "Remove apps and scan leftovers",
                            detail: null,
                            richDetail: new DetailContent
                            {
                                Summary = "Run uninstaller for selected app, then scan for leftover files and registry keys",
                                Changes = new[]
                                {
                                    "Execute application's official uninstaller",
                                    "Scan %AppData%, %LocalAppData%, %ProgramData% for remnants",
                                    "Scan registry for orphaned keys (optional removal)"
                                },
                                Risks = new[]
                                {
                                    "Uninstaller behavior depends on the application",
                                    "Leftover removal is irreversible",
                                    "Review leftovers before using --remove flag"
                                },
                                RollbackInfo = "No automatic rollback - create system restore point first"
                            })
                    })
                });

            _currentMenu = _menuRoot;
            RefreshMenuEntries();
        }

        private void RefreshMenuEntries()
        {
            MenuEntries.Clear();
            if (_currentMenu == null) return;

            if (_currentMenu.Parent != null)
            {
                var backNode = new MenuNode("<- Back", "__back", "Return to previous menu", "Go up one level in the menu tree.");
                MenuEntries.Add(new MenuEntryViewModel(0, backNode) { IsBack = true });
            }

            var index = 1;
            foreach (var node in _currentMenu.Children)
            {
                MenuEntries.Add(new MenuEntryViewModel(index++, node));
            }

            if (MenuEntries.Count > 0)
            {
                _menuIndex = MenuEntries.Count > 1 && MenuEntries[0].IsBack ? 1 : 0;
                MenuEntries[_menuIndex].IsSelected = true;
            }

            UpdateBreadcrumb();
        }

        private void UpdateBreadcrumb()
        {
            if (_currentMenu == null)
            {
                Breadcrumb = "Home";
                BreadcrumbPath = "home";
                return;
            }

            var parts = new List<string>();
            var node = _currentMenu;
            while (node != null)
            {
                parts.Add(node.Title);
                node = node.Parent;
            }

            parts.Reverse();
            Breadcrumb = string.Join(" > ", parts);
            // Lowercase path with forward slashes, excluding "Home" prefix since TGWST is shown in header
            BreadcrumbPath = string.Join(" / ", parts.Skip(1).Select(p => p.ToLowerInvariant()));
        }

        private void NavigateTo(MenuNode node)
        {
            if (!node.HasChildren)
            {
                return;
            }

            _currentMenu = node;
            RefreshMenuEntries();
        }

        public void NavigateBack()
        {
            if (_currentMenu?.Parent == null) return;
            _currentMenu = _currentMenu.Parent;
            RefreshMenuEntries();
        }

        private void MoveMenuSelection(int delta)
        {
            if (MenuEntries.Count == 0) return;
            var next = Math.Clamp(_menuIndex + delta, 0, MenuEntries.Count - 1);
            if (next == _menuIndex) return;
            MenuEntries[_menuIndex].IsSelected = false;
            MenuEntries[_menuIndex].DetailLevel = 0;
            _menuIndex = next;
            MenuEntries[_menuIndex].IsSelected = true;
        }

        public void MenuUp()
        {
            MoveMenuSelection(-1);
        }

        public void MenuDown()
        {
            MoveMenuSelection(1);
        }

        public void ToggleMenuDetails()
        {
            if (MenuEntries.Count == 0) return;
            var entry = MenuEntries[_menuIndex];

            if (!entry.HasAnyDetail) return;

            if (entry.HasRichDetail)
            {
                // Cycle: 0 -> 1 -> 2 -> 0 (collapsed -> summary -> full -> collapsed)
                entry.DetailLevel = (entry.DetailLevel + 1) % 3;
            }
            else
            {
                // Legacy behavior: toggle detail on/off
                entry.DetailLevel = entry.DetailLevel == 0 ? 1 : 0;
            }
        }

        public void SelectMenuEntry(MenuEntryViewModel entry, bool toggleDetails)
        {
            if (entry == null) return;
            var index = MenuEntries.IndexOf(entry);
            if (index < 0) return;

            if (index != _menuIndex)
            {
                MenuEntries[_menuIndex].IsSelected = false;
                MenuEntries[_menuIndex].DetailLevel = 0;
                _menuIndex = index;
                MenuEntries[_menuIndex].IsSelected = true;
            }

            if (toggleDetails && entry.HasAnyDetail)
            {
                entry.DetailLevel = entry.DetailLevel == 0 ? 1 : 0;
            }
        }

        private bool TrySelectMenuByNumber(string cmd)
        {
            if (MenuEntries.Count == 0)
            {
                return false;
            }

            if (!int.TryParse(cmd, out var number))
            {
                return false;
            }

            var selected = MenuEntries.FirstOrDefault(e => e.Index == number);
            if (selected == null)
            {
                return false;
            }

            var index = MenuEntries.IndexOf(selected);
            if (index < 0)
            {
                return false;
            }

            if (index != _menuIndex)
            {
                MenuEntries[_menuIndex].IsSelected = false;
                _menuIndex = index;
                MenuEntries[_menuIndex].IsSelected = true;
            }

            return true;
        }

        private void SetAcronymMode(bool expanded)
        {
            if (_acronymsExpanded == expanded)
            {
                return;
            }

            _acronymsExpanded = expanded;
            var dispatcher = Application.Current?.Dispatcher;

            void Apply()
            {
                foreach (var block in Output)
                {
                    block.DisplayText = _acronymsExpanded
                        ? AcronymExpander.Expand(block.RawText)
                        : block.RawText;
                    block.IsAcronymsExpanded = _acronymsExpanded;
                }

                if (AttachedPane != null)
                {
                    AttachedPane.SetAcronymMode(_acronymsExpanded);
                }
            }

            if (dispatcher?.CheckAccess() == true)
            {
                Apply();
                return;
            }

            dispatcher?.Invoke(Apply);
        }

        public bool AcronymsExpanded => _acronymsExpanded;

        public AttachedPaneSession OpenAttachedPane(string title)
        {
            CloseAttachedPane(force: true);

            var pane = new ProgressViewModel { Title = title };
            pane.SetAcronymMode(_acronymsExpanded);
            AttachedPane = pane;
            _attachedPaneCts = new CancellationTokenSource();
            _attachedPaneCloseConfirm = false;
            OnPropertyChanged(nameof(IsAttachedPaneClosePromptVisible));
            OnPropertyChanged(nameof(AttachedPaneClosePrompt));
            return new AttachedPaneSession(pane, _attachedPaneCts);
        }

        public void RequestCloseAttachedPane()
        {
            if (AttachedPane == null) return;

            if (!_attachedPaneCloseConfirm)
            {
                _attachedPaneCloseConfirm = true;
                OnPropertyChanged(nameof(IsAttachedPaneClosePromptVisible));
                OnPropertyChanged(nameof(AttachedPaneClosePrompt));
                return;
            }

            CloseAttachedPane(force: true);
        }

        public void ClearAttachedPaneClosePrompt()
        {
            if (!_attachedPaneCloseConfirm) return;
            _attachedPaneCloseConfirm = false;
            OnPropertyChanged(nameof(IsAttachedPaneClosePromptVisible));
            OnPropertyChanged(nameof(AttachedPaneClosePrompt));
        }

        public void CloseAttachedPane(bool force)
        {
            if (AttachedPane == null) return;
            if (!force && !_attachedPaneCloseConfirm)
            {
                _attachedPaneCloseConfirm = true;
                OnPropertyChanged(nameof(IsAttachedPaneClosePromptVisible));
                OnPropertyChanged(nameof(AttachedPaneClosePrompt));
                return;
            }

            _attachedPaneCts?.Cancel();
            _attachedPaneCts = null;
            AttachedPane = null;
            _attachedPaneCloseConfirm = false;
            OnPropertyChanged(nameof(IsAttachedPaneClosePromptVisible));
            OnPropertyChanged(nameof(AttachedPaneClosePrompt));
        }

        private static bool IsAdministrator()
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void UpdatePromptPrefix(bool isAdmin)
        {
            PromptPrefix = isAdmin
                ? $"tgwst [Administrator] {DefaultStatus} > "
                : $"tgwst {DefaultStatus} > ";
        }
    }

    public sealed class MenuEntryViewModel : ObservableObject
    {
        public MenuEntryViewModel(int index, MenuNode node)
        {
            Index = index;
            Node = node;
        }

        public int Index { get; }
        public MenuNode Node { get; }
        public string IndexLabel => $"{Index}.";
        public string Title => Node.Title;
        public string Subtitle => Node.Description ?? (Node.HasChildren ? "Open menu" : "Execute");
        public string Detail => Node.Detail ?? string.Empty;

        // Rich detail support
        public DetailContent? RichDetail => Node.RichDetail;
        public bool HasRichDetail => RichDetail != null;
        public bool HasAnyDetail => HasRichDetail || !string.IsNullOrWhiteSpace(Detail);

        private bool _isBack;
        public bool IsBack
        {
            get => _isBack;
            set => SetProperty(ref _isBack, value);
        }

        private bool _isSelected;
        public bool IsSelected
        {
            get => _isSelected;
            set => SetProperty(ref _isSelected, value);
        }

        // Detail expansion level: 0=collapsed, 1=summary, 2=full
        private int _detailLevel;
        public int DetailLevel
        {
            get => _detailLevel;
            set
            {
                if (SetProperty(ref _detailLevel, value))
                {
                    OnPropertyChanged(nameof(ShowSummary));
                    OnPropertyChanged(nameof(ShowFullDetail));
                    OnPropertyChanged(nameof(ShowDetails));
                }
            }
        }

        public bool ShowSummary => _detailLevel >= 1;
        public bool ShowFullDetail => _detailLevel >= 2;

        // Legacy compatibility - ShowDetails maps to any detail visible
        public bool ShowDetails
        {
            get => _detailLevel > 0;
            set => DetailLevel = value ? 1 : 0;
        }

        // Computed display strings for rich details
        public string ChangesDisplay => RichDetail?.Changes is { Length: > 0 }
            ? string.Join("\n", RichDetail.Changes.Select(c => $"  • {c}"))
            : "";

        public string RisksDisplay => RichDetail?.Risks is { Length: > 0 }
            ? string.Join("\n", RichDetail.Risks.Select(r => $"  ! {r}"))
            : "";
    }
}
