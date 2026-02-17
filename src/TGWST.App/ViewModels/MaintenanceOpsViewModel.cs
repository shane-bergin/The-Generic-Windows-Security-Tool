using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using TGWST.App.Services;
using TGWST.Core.Audit;
using TGWST.Core.EventLog;
using TGWST.Core.Junk;
using TGWST.Core.Recovery;
using TGWST.Core.ServicesAnalysis;

namespace TGWST.App.ViewModels
{
    public sealed partial class MaintenanceOpsViewModel : ObservableObject
    {
        private readonly DeletedFileRecoveryEngine _recoveryEngine;
        private readonly ServiceAnalyzerEngine _serviceAnalyzer;
        private readonly JunkAnalyzerEngine _junkAnalyzer;
        private readonly EventLogAnalyzer _eventLogAnalyzer;
        private readonly OperationCoordinatorService _operationCoordinator;
        private readonly AuditLogService _audit;

        private readonly List<ServiceAnalysisItem> _allServices = new();
        private readonly List<EventLogFinding> _allEventFindings = new();
        private CancellationTokenSource? _activeCts;

        public ObservableCollection<RecoveryRow> RecoveryItems { get; } = new();
        public ObservableCollection<ServiceRow> ServiceItems { get; } = new();
        public ObservableCollection<JunkRow> JunkItems { get; } = new();
        public ObservableCollection<EventLogRow> EventItems { get; } = new();

        [ObservableProperty]
        private string _footerText = "Ready.";

        [ObservableProperty]
        private string _currentOperation = string.Empty;

        [ObservableProperty]
        private bool _isBusy;

        [ObservableProperty]
        private string _recoverySourceDrive = "C:";

        [ObservableProperty]
        private string _recoveryDestinationRoot = string.Empty;

        [ObservableProperty]
        private RecoveryRow? _selectedRecoveryItem;

        [ObservableProperty]
        private string _recoveryPreviewText = "Select an item and click Preview.";

        [ObservableProperty]
        private string? _recoveryPreviewImagePath;

        [ObservableProperty]
        private bool _showRecoveryImagePreview;

        [ObservableProperty]
        private bool _showNonEssentialServicesOnly;

        [ObservableProperty]
        private ServiceRow? _selectedServiceItem;

        [ObservableProperty]
        private string _serviceStatusText = "Services not analyzed yet.";

        [ObservableProperty]
        private string _serviceInspectorPreviewText =
            "Select a service row to review wrapped details. Double-click a row or use Inspect Selected.";

        [ObservableProperty]
        private string _junkStatusText = "No junk analysis run yet.";

        [ObservableProperty]
        private JunkRow? _selectedJunkItem;

        [ObservableProperty]
        private string _junkInspectorPreviewText =
            "Select a junk candidate row to inspect details. Double-click a row or use Inspect Selected.";

        [ObservableProperty]
        private int _eventLookbackDays = 10;

        [ObservableProperty]
        private bool _showDrasticEventsOnly;

        [ObservableProperty]
        private EventLogRow? _selectedEventItem;

        [ObservableProperty]
        private string _eventDetailText = "Select a finding to inspect details.";

        [ObservableProperty]
        private string _eventStatusText = "No event analysis run yet.";

        public IReadOnlyList<int> EventLookbackOptions { get; } = new[] { 7, 10, 14 };

        public bool HasActiveOperation => _activeCts != null;

        public MaintenanceOpsViewModel(
            DeletedFileRecoveryEngine recoveryEngine,
            ServiceAnalyzerEngine serviceAnalyzer,
            JunkAnalyzerEngine junkAnalyzer,
            EventLogAnalyzer eventLogAnalyzer,
            OperationCoordinatorService operationCoordinator,
            AuditLogService audit)
        {
            _recoveryEngine = recoveryEngine;
            _serviceAnalyzer = serviceAnalyzer;
            _junkAnalyzer = junkAnalyzer;
            _eventLogAnalyzer = eventLogAnalyzer;
            _operationCoordinator = operationCoordinator;
            _audit = audit;

            var systemRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
            RecoverySourceDrive = systemRoot.Length >= 2 ? systemRoot[..2] : "C:";
            RecoveryDestinationRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "TGWST-Recovered");
        }

        partial void OnShowNonEssentialServicesOnlyChanged(bool value)
        {
            ApplyServiceFilter();
        }

        partial void OnShowDrasticEventsOnlyChanged(bool value)
        {
            ApplyEventFilter();
        }

        partial void OnSelectedServiceItemChanged(ServiceRow? value)
        {
            if (value == null)
            {
                ServiceInspectorPreviewText =
                    "Select a service row to review wrapped details. Double-click a row or use Inspect Selected.";
                return;
            }

            ServiceInspectorPreviewText =
                $"Service: {value.ServiceName} ({value.DisplayName}){Environment.NewLine}" +
                $"Status: {value.Status} | Startup: {value.StartupType} | {value.StateNote}{Environment.NewLine}" +
                $"Origin: {value.Origin} | Essential: {value.Essential} | Impact: {value.ImpactLabel}{Environment.NewLine}{Environment.NewLine}" +
                $"Purpose: {value.Purpose}{Environment.NewLine}{Environment.NewLine}" +
                $"Keep Enabled When: {value.KeepEnabledReason}{Environment.NewLine}{Environment.NewLine}" +
                $"Disable When: {value.DisableReason}{Environment.NewLine}{Environment.NewLine}" +
                $"Recommendation: {value.Recommendation}";
        }

        partial void OnSelectedEventItemChanged(EventLogRow? value)
        {
            if (value == null)
            {
                EventDetailText = "Select a finding to inspect details.";
                return;
            }

            var rawMessage = value.Message?.Trim();
            var messageText = !string.IsNullOrWhiteSpace(rawMessage) ? rawMessage : value.Summary;

            EventDetailText =
                $"Time: {value.TimeCreated:g}{Environment.NewLine}" +
                $"Severity: {value.Severity} | Importance: {value.Importance} | Drastic: {value.IsDrastic}{Environment.NewLine}" +
                $"Event: {value.EventId} | Log: {value.LogName} | Source: {value.Source}{Environment.NewLine}" +
                $"Rule: {value.Rule}{Environment.NewLine}{Environment.NewLine}" +
                $"Purpose: {value.Purpose}{Environment.NewLine}{Environment.NewLine}" +
                $"Why It Matters: {value.WhyItMatters}{Environment.NewLine}{Environment.NewLine}" +
                $"Recommendation: {value.Recommendation}{Environment.NewLine}{Environment.NewLine}" +
                $"Message: {messageText}";
        }

        partial void OnSelectedJunkItemChanged(JunkRow? value)
        {
            if (value == null)
            {
                JunkInspectorPreviewText =
                    "Select a junk candidate row to inspect details. Double-click a row or use Inspect Selected.";
                return;
            }

            JunkInspectorPreviewText =
                $"Path: {value.Path}{Environment.NewLine}" +
                $"Kind: {value.Kind} | Category: {value.Category}{Environment.NewLine}" +
                $"Size: {value.SizeDisplay} | Modified: {value.LastModified:g}{Environment.NewLine}" +
                $"Safety: {value.SafetyLabel}{Environment.NewLine}{Environment.NewLine}" +
                $"Reason: {value.Reason}{Environment.NewLine}{Environment.NewLine}" +
                $"Purpose: {value.Purpose}{Environment.NewLine}{Environment.NewLine}" +
                $"Why It Matters: {value.WhyItMatters}{Environment.NewLine}{Environment.NewLine}" +
                $"Recommendation: {value.Recommendation}";
        }

        public void CancelActiveOperation()
        {
            if (_activeCts == null)
            {
                return;
            }

            _activeCts.Cancel();
            FooterText = "Cancel requested...";
        }

        public async Task ScanRecoveryAsync()
        {
            if (!TryBeginOperation("Deleted File Recovery Scan", out var lease, out var ct))
            {
                return;
            }

            try
            {
                RecoveryPreviewText = "Scanning...";
                RecoveryPreviewImagePath = null;
                ShowRecoveryImagePreview = false;

                var result = await _recoveryEngine.ScanAsync(
                    RecoverySourceDrive,
                    RecoveryDestinationRoot,
                    ct);

                UpdateRecoveryItems(result.Items);
                FooterText = result.StatusMessage;
                RecoveryPreviewText = result.Items.Count == 0
                    ? "No recoverable candidates found for the selected mode."
                    : "Select a candidate and click Preview.";
            }
            catch (OperationCanceledException)
            {
                FooterText = "Recovery scan canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Recovery scan failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        public async Task PreviewSelectedRecoveryAsync()
        {
            var item = SelectedRecoveryItem?.Model;
            if (item == null)
            {
                RecoveryPreviewText = "Select a recovery candidate first.";
                return;
            }

            if (!TryBeginOperation("Deleted File Recovery Preview", out var lease, out var ct))
            {
                return;
            }

            try
            {
                var preview = await _recoveryEngine.BuildPreviewAsync(item, ct);
                ShowRecoveryImagePreview = preview.Kind == RecoveryPreviewKind.Image;
                RecoveryPreviewImagePath = preview.ImagePath;
                RecoveryPreviewText = preview.Content;
                FooterText = $"Preview ready for {item.FileName}.";
            }
            catch (OperationCanceledException)
            {
                FooterText = "Preview canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Preview failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        public async Task RestoreSelectedRecoveryAsync()
        {
            var item = SelectedRecoveryItem?.Model;
            if (item == null)
            {
                FooterText = "Select a recovery candidate first.";
                return;
            }

            if (!TryBeginOperation("Deleted File Recovery Restore", out var lease, out var ct))
            {
                return;
            }

            try
            {
                var result = await _recoveryEngine.RestoreAsync(
                    item,
                    RecoveryDestinationRoot,
                    ct);

                FooterText = result.Success
                    ? $"Restored to: {result.RestoredPath}"
                    : $"[X] Restore failed: {result.Message}";

                if (result.Success)
                {
                    _audit.Write(
                        action: "Recovery.Restore",
                        details: $"source={item.SourcePath};restored={result.RestoredPath}",
                        correlationId: Guid.NewGuid().ToString("N"),
                        privileged: true);
                }
            }
            catch (OperationCanceledException)
            {
                FooterText = "Restore canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Restore failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        public async Task AnalyzeServicesAsync()
        {
            if (!TryBeginOperation("Services Analysis", out var lease, out var ct))
            {
                return;
            }

            try
            {
                await RefreshServicesInternalAsync(ct);
                FooterText = "Services analysis completed.";
            }
            catch (OperationCanceledException)
            {
                FooterText = "Services analysis canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Services analysis failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        public async Task DisableSelectedServiceAsync()
        {
            var row = SelectedServiceItem;
            if (row == null)
            {
                FooterText = "Select a service first.";
                return;
            }

            if (row.Essential)
            {
                FooterText = "Selected service is protected and cannot be disabled.";
                return;
            }

            if (!TryBeginOperation("Service Disable", out var lease, out var ct))
            {
                return;
            }

            try
            {
                var result = await _serviceAnalyzer.DisableAsync(row.ServiceName, ct);
                FooterText = result.Success ? result.Message : $"[X] {result.Message}";
                if (result.Success)
                {
                    _audit.Write(
                        action: "Service.Disable",
                        details: $"service={row.ServiceName}",
                        correlationId: Guid.NewGuid().ToString("N"),
                        privileged: true);
                }

                await RefreshServicesInternalAsync(ct);
            }
            catch (OperationCanceledException)
            {
                FooterText = "Service disable canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Service disable failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        public async Task RestoreSelectedServiceAsync()
        {
            var row = SelectedServiceItem;
            if (row == null)
            {
                FooterText = "Select a service first.";
                return;
            }

            if (!TryBeginOperation("Service Restore", out var lease, out var ct))
            {
                return;
            }

            try
            {
                var result = await _serviceAnalyzer.RestoreAsync(row.ServiceName, ct);
                FooterText = result.Success ? result.Message : $"[X] {result.Message}";
                if (result.Success)
                {
                    _audit.Write(
                        action: "Service.Restore",
                        details: $"service={row.ServiceName}",
                        correlationId: Guid.NewGuid().ToString("N"),
                        privileged: true);
                }

                await RefreshServicesInternalAsync(ct);
            }
            catch (OperationCanceledException)
            {
                FooterText = "Service restore canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Service restore failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        public async Task AnalyzeJunkAsync()
        {
            if (!TryBeginOperation("Junk Analysis", out var lease, out var ct))
            {
                return;
            }

            try
            {
                await RefreshJunkInternalAsync(ct);
                FooterText = "Junk analysis completed.";
            }
            catch (OperationCanceledException)
            {
                FooterText = "Junk analysis canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Junk analysis failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        public async Task CleanSelectedJunkAsync()
        {
            var selected = JunkItems.Where(x => x.IsSelected).ToArray();
            if (selected.Length == 0)
            {
                FooterText = "Select one or more junk candidates first.";
                return;
            }

            await CleanupJunkAsync(selected.Select(x => x.Model).ToArray());
        }

        public async Task CleanAllSafeJunkAsync()
        {
            var safe = JunkItems.Where(x => x.SafeToClean).Select(x => x.Model).ToArray();
            if (safe.Length == 0)
            {
                FooterText = "No safe junk candidates are currently listed.";
                return;
            }

            await CleanupJunkAsync(safe);
        }

        public async Task AnalyzeEventLogsAsync()
        {
            if (!TryBeginOperation("Event Log Analysis", out var lease, out var ct))
            {
                return;
            }

            try
            {
                var lookback = TimeSpan.FromDays(EventLookbackDays <= 0 ? 10 : EventLookbackDays);
                var findings = await _eventLogAnalyzer.ScanAsync(lookback, ct);
                UpdateEventItems(findings);

                var drastic = findings.Count(x => x.IsDrastic);
                var important = findings.Count(x => !x.IsDrastic && x.Importance.Equals("Important", StringComparison.OrdinalIgnoreCase));
                var typical = findings.Count - drastic - important;

                EventStatusText =
                    $"{findings.Count} findings in last {lookback.TotalDays:0} days | drastic={drastic} | important={important} | typical={typical}";
                FooterText = "Event log analysis completed.";
            }
            catch (OperationCanceledException)
            {
                FooterText = "Event log analysis canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Event log analysis failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        private async Task CleanupJunkAsync(IReadOnlyList<JunkCandidate> targets)
        {
            if (!TryBeginOperation("Junk Cleanup", out var lease, out var ct))
            {
                return;
            }

            try
            {
                var result = await _junkAnalyzer.CleanupAsync(targets, safeOnly: true, ct);
                FooterText = $"Cleanup completed. Deleted={result.DeletedCount}, skipped={result.SkippedCount}.";

                _audit.Write(
                    action: "Junk.Cleanup",
                    details: $"requested={targets.Count};deleted={result.DeletedCount};skipped={result.SkippedCount}",
                    correlationId: Guid.NewGuid().ToString("N"),
                    privileged: true);

                await RefreshJunkInternalAsync(ct);
            }
            catch (OperationCanceledException)
            {
                FooterText = "Junk cleanup canceled.";
            }
            catch (Exception ex)
            {
                FooterText = $"[X] Junk cleanup failed: {ex.Message}";
            }
            finally
            {
                EndOperation(lease);
            }
        }

        private async Task RefreshServicesInternalAsync(CancellationToken ct)
        {
            var snapshot = await _serviceAnalyzer.AnalyzeAsync(ct);
            _allServices.Clear();
            _allServices.AddRange(snapshot.Services);
            ApplyServiceFilter();

            var essential = snapshot.Services.Count(x => x.Essential);
            var nonEssential = snapshot.Services.Count - essential;
            var nonEssentialRunning = snapshot.Services.Count(x =>
                !x.Essential &&
                x.Status.Equals("Running", StringComparison.OrdinalIgnoreCase));
            var nonEssentialDisabled = snapshot.Services.Count(x =>
                !x.Essential &&
                x.StartupType.Equals("Disabled", StringComparison.OrdinalIgnoreCase));
            var highImpact = snapshot.Services.Count(x => x.HighImpact);

            ServiceStatusText =
                $"{snapshot.Services.Count} services analyzed | essential={essential} | non-essential={nonEssential} | non-essential running={nonEssentialRunning} | non-essential disabled={nonEssentialDisabled} | high-impact={highImpact}";
        }

        private async Task RefreshJunkInternalAsync(CancellationToken ct)
        {
            var items = await _junkAnalyzer.AnalyzeAsync(ct);
            UpdateJunkItems(items);
            var safe = items.Count(x => x.SafeToClean);
            JunkStatusText = $"{items.Count} candidates found | safe={safe} | review before cleanup.";
        }

        private void UpdateRecoveryItems(IReadOnlyList<DeletedFileRecoveryItem> items)
        {
            RunOnUi(() =>
            {
                RecoveryItems.Clear();
                foreach (var item in items)
                {
                    RecoveryItems.Add(new RecoveryRow(item));
                }

                SelectedRecoveryItem = RecoveryItems.FirstOrDefault();
            });
        }

        private void ApplyServiceFilter()
        {
            RunOnUi(() =>
            {
                ServiceItems.Clear();
                var filtered = ShowNonEssentialServicesOnly
                    ? _allServices.Where(x => !x.Essential)
                    : _allServices.AsEnumerable();

                foreach (var svc in filtered)
                {
                    ServiceItems.Add(new ServiceRow(svc));
                }

                SelectedServiceItem = ServiceItems.FirstOrDefault();
            });
        }

        private void UpdateJunkItems(IReadOnlyList<JunkCandidate> items)
        {
            RunOnUi(() =>
            {
                JunkItems.Clear();
                foreach (var item in items)
                {
                    JunkItems.Add(new JunkRow(item) { IsSelected = item.SafeToClean });
                }

                SelectedJunkItem = JunkItems.FirstOrDefault();
            });
        }

        private void UpdateEventItems(IReadOnlyList<EventLogFinding> items)
        {
            _allEventFindings.Clear();
            _allEventFindings.AddRange(items);
            ApplyEventFilter();
        }

        private void ApplyEventFilter()
        {
            RunOnUi(() =>
            {
                EventItems.Clear();
                var filtered = ShowDrasticEventsOnly
                    ? _allEventFindings.Where(x => x.IsDrastic)
                    : _allEventFindings.AsEnumerable();

                foreach (var finding in filtered)
                {
                    EventItems.Add(new EventLogRow(finding));
                }

                SelectedEventItem = EventItems.FirstOrDefault();
            });
        }

        private bool TryBeginOperation(string operationName, out IDisposable? lease, out CancellationToken ct)
        {
            lease = null;
            ct = default;

            if (!_operationCoordinator.TryAcquireHeavy(operationName, out lease, out var owner))
            {
                FooterText = $"[X] Busy: '{owner}'. Wait for the current heavy task to finish.";
                return false;
            }

            _activeCts = new CancellationTokenSource();
            ct = _activeCts.Token;
            IsBusy = true;
            CurrentOperation = operationName;
            OnPropertyChanged(nameof(HasActiveOperation));
            FooterText = $"{operationName} started...";
            return true;
        }

        private void EndOperation(IDisposable? lease)
        {
            try
            {
                _activeCts?.Dispose();
            }
            catch
            {
                // best effort cleanup
            }
            finally
            {
                _activeCts = null;
                IsBusy = false;
                CurrentOperation = string.Empty;
                OnPropertyChanged(nameof(HasActiveOperation));
                lease?.Dispose();
            }
        }

        private static void RunOnUi(Action action)
        {
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher == null || dispatcher.CheckAccess())
            {
                action();
                return;
            }

            dispatcher.Invoke(action);
        }
    }

    public sealed partial class RecoveryRow : ObservableObject
    {
        public RecoveryRow(DeletedFileRecoveryItem model)
        {
            Model = model;
        }

        public DeletedFileRecoveryItem Model { get; }
        public string FileName => Model.FileName;
        public string FileType => Model.FileType;
        public long FileSize => Model.FileSize;
        public string FileSizeDisplay => FormatBytes(Model.FileSize);
        public DateTime DateModified => Model.DateModified;
        public string Source => Model.Source;

        private static string FormatBytes(long size)
        {
            if (size <= 0) return "0 B";
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            var value = size;
            var unit = 0;
            double scaled = value;
            while (scaled >= 1024 && unit < units.Length - 1)
            {
                scaled /= 1024;
                unit++;
            }

            return $"{scaled:0.##} {units[unit]}";
        }
    }

    public sealed class ServiceRow
    {
        public ServiceRow(ServiceAnalysisItem model)
        {
            Model = model;
        }

        public ServiceAnalysisItem Model { get; }
        public string ServiceName => Model.ServiceName;
        public string DisplayName => Model.DisplayName;
        public string Status => Model.Status;
        public string StartupType => Model.StartupType;
        public string StateNote => Model.StateNote;
        public string Origin => Model.Origin;
        public bool Essential => Model.Essential;
        public string Reason => Model.Reason;
        public bool HighImpact => Model.HighImpact;
        public string ImpactLabel => HighImpact ? "HIGH IMPACT" : "Normal";
        public string Purpose => Model.Purpose;
        public string KeepEnabledReason => Model.KeepEnabledReason;
        public string DisableReason => Model.DisableReason;
        public string Recommendation => Model.Recommendation;
        public string RecommendationSummary => $"{Reason} {Recommendation}".Trim();
        public string TableSummary => BuildShortSummary(RecommendationSummary, 120);

        private static string BuildShortSummary(string value, int maxLength)
        {
            var normalized = (value ?? string.Empty).Replace('\r', ' ').Replace('\n', ' ').Trim();
            if (normalized.Length <= maxLength)
            {
                return normalized;
            }

            return normalized[..(maxLength - 3)] + "...";
        }
    }

    public sealed partial class JunkRow : ObservableObject
    {
        public JunkRow(JunkCandidate model)
        {
            Model = model;
        }

        public JunkCandidate Model { get; }
        public string Path => Model.Path;
        public string Kind => Model.Kind;
        public long SizeBytes => Model.SizeBytes;
        public string SizeDisplay => FormatBytes(Model.SizeBytes);
        public DateTime LastModified => Model.LastModified;
        public string Category => Model.Category;
        public string Reason => Model.Reason;
        public bool SafeToClean => Model.SafeToClean;
        public string SafetyLabel => SafeToClean ? "Safe Candidate" : "Review Required";
        public string Importance => SafeToClean ? "Typical Cleanup Candidate" : "Potentially Sensitive";
        public string Purpose => BuildPurpose(Model.Category, Model.Kind);
        public string WhyItMatters => BuildWhyItMatters(SafeToClean, Model.Category);
        public string Recommendation => BuildRecommendation(SafeToClean, Model.Category);
        public string InspectorKey => Model.ItemId;

        [ObservableProperty]
        private bool _isSelected;

        private static string FormatBytes(long size)
        {
            if (size <= 0) return "0 B";
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            var value = size;
            var unit = 0;
            double scaled = value;
            while (scaled >= 1024 && unit < units.Length - 1)
            {
                scaled /= 1024;
                unit++;
            }

            return $"{scaled:0.##} {units[unit]}";
        }

        private static string BuildPurpose(string category, string kind)
        {
            if (category.Contains("Telemetry/Tracking", StringComparison.OrdinalIgnoreCase))
            {
                return "Likely telemetry/cache residue left by application or browsing workflows.";
            }

            if (kind.Equals("Directory", StringComparison.OrdinalIgnoreCase))
            {
                return "Container holding stale temp/cache artifacts that accumulate over time.";
            }

            return "Temporary/cache artifact generated by applications or the OS.";
        }

        private static string BuildWhyItMatters(bool safeToClean, string category)
        {
            if (!safeToClean)
            {
                return "This item was not marked safe by heuristic rules and may still be referenced by an application.";
            }

            if (category.Contains("Telemetry/Tracking", StringComparison.OrdinalIgnoreCase))
            {
                return "Removing stale telemetry/cache residue can reduce clutter and some passive tracking footprint.";
            }

            return "Removing stale temp/cache files can reclaim disk space and reduce cleanup debt.";
        }

        private static string BuildRecommendation(bool safeToClean, string category)
        {
            if (!safeToClean)
            {
                return "Inspect first; only delete after confirming no application dependency.";
            }

            if (category.Contains("Telemetry/Tracking", StringComparison.OrdinalIgnoreCase))
            {
                return "Generally safe to clean when stale; prefer app-closed cleanup windows.";
            }

            return "Safe candidate for cleanup; keep recent/actively modified artifacts if troubleshooting is in progress.";
        }
    }

    public sealed class EventLogRow
    {
        public EventLogRow(EventLogFinding model)
        {
            Model = model;
        }

        public EventLogFinding Model { get; }
        public DateTime TimeCreated => Model.TimeCreated;
        public string Severity => Model.Severity;
        public string Importance => Model.Importance;
        public bool IsDrastic => Model.IsDrastic;
        public int EventId => Model.EventId;
        public string LogName => Model.LogName;
        public string Source => Model.Source ?? "-";
        public string Rule => Model.Rule;
        public string Summary => Model.Summary;
        public string SummaryShort => BuildShortSummary(Model.Summary, 120);
        public string Purpose => Model.Purpose;
        public string WhyItMatters => Model.WhyItMatters;
        public string Recommendation => Model.Recommendation;
        public int Count => Model.Count;
        public string? Message => Model.Message;
        public string MessageDisplay => string.IsNullOrWhiteSpace(Model.Message) ? Model.Summary : Model.Message!;
        public string InspectorKey => $"{LogName}|{EventId}|{Rule}|{TimeCreated:O}";

        private static string BuildShortSummary(string value, int maxLength)
        {
            var normalized = (value ?? string.Empty).Replace('\r', ' ').Replace('\n', ' ').Trim();
            if (normalized.Length <= maxLength)
            {
                return normalized;
            }

            return normalized[..(maxLength - 3)] + "...";
        }
    }
}
