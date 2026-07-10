using System;
using System.Linq;

namespace TGWST.App.ViewModels;

public enum CyberSeverity
{
    Info,
    Success,
    Warning,
    Critical
}

public enum CyberThreatLevel
{
    Normal,
    Elevated,
    Critical
}

public sealed record SecurityLogEntry(
    DateTimeOffset Timestamp,
    CyberSeverity Severity,
    string Source,
    string Message,
    string Detail = "",
    string Impact = "",
    string RecommendedAction = "",
    string LinkLabel = "",
    string LinkTarget = "")
{
    public string Time => Timestamp.ToString("HH:mm:ss");
    public string SeverityLabel => Severity.ToString().ToUpperInvariant();
    public string DisplayLine => $"[{Timestamp:HH:mm:ss}] [{Severity.ToString().ToUpperInvariant()}] {Source} :: {Message}";
    public bool HasLink => !string.IsNullOrWhiteSpace(LinkTarget);
    public string LinkText => HasLink
        ? string.IsNullOrWhiteSpace(LinkLabel) ? "OPEN" : LinkLabel
        : "-";
    public string ToolTip => string.Join(Environment.NewLine, new[]
    {
        DisplayLine,
        string.IsNullOrWhiteSpace(Detail) ? null : $"Detail: {Detail}",
        string.IsNullOrWhiteSpace(Impact) ? null : $"Impact: {Impact}",
        string.IsNullOrWhiteSpace(RecommendedAction) ? null : $"Action: {RecommendedAction}"
    }.Where(line => !string.IsNullOrWhiteSpace(line)));
}

public sealed record NetworkConnectionRow(
    string Process,
    int ProcessId,
    string Protocol,
    string ProtocolType,
    string Service,
    string Local,
    string LocalAddress,
    int LocalPort,
    string Remote,
    string RemoteAddress,
    int RemotePort,
    string State,
    int RiskScore,
    string Risk,
    string ProtocolConcern,
    string ProtocolInspection,
    string? RemoteHost = null,
    string? Anomaly = null,
    string Category = "Unknown",
    DateTimeOffset? ProcessStartTime = null,
    string? ExecutablePath = null)
{
    public bool HasProcess => ProcessId > 0;
    public bool HasRemoteAddress => !string.IsNullOrWhiteSpace(RemoteAddress) &&
                                    RemoteAddress != "*" &&
                                    RemoteAddress != "0.0.0.0" &&
                                    RemoteAddress != "::";

    public bool IsListener => State.Equals("LISTEN", StringComparison.OrdinalIgnoreCase);

    public bool IsUdpSocket => Protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase) && !HasRemoteAddress;

    public string BlueTeamSignal => IsListener
        ? "EXPOSED LISTENER"
        : IsUdpSocket
            ? "UDP SOCKET"
            : HasRemoteAddress
                ? "REMOTE SESSION"
                : "LOCAL SOCKET";

    public string ToolTip => ProtocolInspection;
}

public sealed record DeepNetworkFindingRow(
    string Severity,
    string Category,
    string Subject,
    string Explanation,
    string RecommendedAction);

public sealed record DeepNetworkEndpointRow(
    string Classification,
    int RiskScore,
    string Process,
    int ProcessId,
    string ProcessPath,
    string RemoteAddress,
    int RemotePort,
    string RemoteHost,
    string DnsRecords,
    string Route,
    string GeoNetwork,
    string Explanation)
{
    public string Endpoint => RemotePort > 0 ? $"{RemoteAddress}:{RemotePort}" : RemoteAddress;
    public string ToolTip => $"{Classification} risk={RiskScore}/100{Environment.NewLine}{Explanation}{Environment.NewLine}Route: {Route}{Environment.NewLine}DNS: {DnsRecords}{Environment.NewLine}Network: {GeoNetwork}";
}

public sealed record DeepNetworkRouteRow(
    string DestinationPrefix,
    string NextHop,
    string InterfaceAlias,
    int RouteMetric,
    int InterfaceMetric,
    string Protocol,
    string State,
    string Assessment);

public sealed record DeepNetworkDnsRow(
    string Name,
    string RecordType,
    string Data,
    string Source,
    string Assessment);

public sealed record DeepNetworkAnalysisSnapshot(
    DateTimeOffset Timestamp,
    string Summary,
    IReadOnlyList<DeepNetworkFindingRow> Findings,
    IReadOnlyList<DeepNetworkEndpointRow> Endpoints,
    IReadOnlyList<DeepNetworkRouteRow> Routes,
    IReadOnlyList<DeepNetworkDnsRow> DnsRecords);

public enum DashboardFindingAction
{
    None,
    EnableDefenderProtection,
    ApplyWindowsSecurityBaseline,
    EnableFirewall,
    ApplyFirewallBaseline,
    BlockTopNetworkRisk
}

public sealed record DashboardFindingRow(
    string Severity,
    string Area,
    string Detail,
    string RecommendedAction,
    string Explanation = "",
    string PotentialImpact = "",
    DashboardFindingAction Action = DashboardFindingAction.None,
    string ActionLabel = "",
    string AutomationScope = "",
    string Verification = "",
    bool RequiresElevation = false)
{
    public bool HasAutomatedAction => Action != DashboardFindingAction.None;

    public string ActionButtonText => HasAutomatedAction
        ? $"[ {ActionLabel.ToUpperInvariant()} ]"
        : "[ MANUAL REVIEW ]";

    public string EvidenceConfidence => Area.Equals("Collection", StringComparison.OrdinalIgnoreCase)
        ? "DEGRADED"
        : "OBSERVED";

    public string ElevationText => RequiresElevation
        ? "UAC elevation required. The action will not run silently."
        : "No elevation is requested by this action.";

    public string AutomationScopeText => string.IsNullOrWhiteSpace(AutomationScope)
        ? "No automatic change is offered for this finding."
        : AutomationScope;

    public string VerificationText => string.IsNullOrWhiteSpace(Verification)
        ? "Refresh the relevant evidence source and confirm the finding state changed."
        : Verification;

    public string ToolTip => string.Join(Environment.NewLine, new[]
    {
        $"[{Severity}] {Area}: {Detail}",
        string.IsNullOrWhiteSpace(Explanation) ? null : $"Why: {Explanation}",
        string.IsNullOrWhiteSpace(PotentialImpact) ? null : $"Impact: {PotentialImpact}",
        string.IsNullOrWhiteSpace(RecommendedAction) ? null : $"Action: {RecommendedAction}",
        string.IsNullOrWhiteSpace(Verification) ? null : $"Verify: {Verification}"
    }.Where(line => !string.IsNullOrWhiteSpace(line)));
}

public sealed record PortProbeRow(
    string Address,
    int Port,
    string Service,
    string Status,
    string Risk,
    string Detail,
    string Recommendation)
{
    public string Endpoint => $"{Address}:{Port}";
    public string ToolTip => $"{Endpoint} {Service} {Status}{Environment.NewLine}{Detail}{Environment.NewLine}{Recommendation}";
}

public sealed record TelemetryEventRow(
    DateTimeOffset Timestamp,
    CyberSeverity Severity,
    string Source,
    string Signal,
    string Subject,
    string Detail,
    int? ProcessId = null,
    int? ParentProcessId = null,
    string ParentProcess = "",
    string Impact = "",
    string RecommendedAction = "",
    string LinkLabel = "",
    string LinkTarget = "")
{
    public string Time => Timestamp.ToString("HH:mm:ss");
    public string SeverityLabel => Severity.ToString().ToUpperInvariant();
    public string ProcessIdText => ProcessId?.ToString() ?? "-";
    public string ParentText => ParentProcessId.HasValue
        ? string.IsNullOrWhiteSpace(ParentProcess)
            ? ParentProcessId.Value.ToString()
            : $"{ParentProcess} ({ParentProcessId.Value})"
        : "-";
    public string DisplayLine => $"[{Timestamp:HH:mm:ss}] [{SeverityLabel}] {Source} :: {Signal} :: {Subject} :: {Detail}";
    public bool HasLink => !string.IsNullOrWhiteSpace(LinkTarget);
    public string LinkText => HasLink
        ? string.IsNullOrWhiteSpace(LinkLabel) ? "OPEN" : LinkLabel
        : "-";
    public string ToolTip => string.Join(Environment.NewLine, new[]
    {
        DisplayLine,
        string.IsNullOrWhiteSpace(Impact) ? null : $"Impact: {Impact}",
        string.IsNullOrWhiteSpace(RecommendedAction) ? null : $"Action: {RecommendedAction}"
    }.Where(line => !string.IsNullOrWhiteSpace(line)));
}

public sealed record RiskTimelineItem(string Label, int Info, int Warning, int Critical);

public sealed record StartupAuditRow(
    string Scope,
    string Name,
    string Executable,
    string Risk,
    string Reason);

public sealed record EventFindingRow(
    string Severity,
    string Rule,
    int Count,
    string Recommendation);

public sealed record JunkFindingRow(
    string Kind,
    string Category,
    int Count,
    string Size,
    string Risk);

public sealed record ToolResult(bool Success, string Message);

public sealed record InstalledAppRow(
    string Name,
    string Version,
    string Publisher,
    string InstallLocation,
    string UninstallString,
    string QuietUninstallString,
    string RegistryKey,
    string Scope,
    string Risk,
    string Concern)
{
    public string DisplayVersion => string.IsNullOrWhiteSpace(Version) ? "-" : Version;
    public string DisplayPublisher => string.IsNullOrWhiteSpace(Publisher) ? "Unknown" : Publisher;
    public bool HasUninstaller => !string.IsNullOrWhiteSpace(UninstallString) || !string.IsNullOrWhiteSpace(QuietUninstallString);
    public string ToolTip => $"{Name} {DisplayVersion}{Environment.NewLine}{Concern}{Environment.NewLine}Registry: {RegistryKey}";
}

public sealed record CleanerResidueRow(
    string Kind,
    string Target,
    string Size,
    string Risk,
    string Detail,
    bool SafeToClean)
{
    public string SafeText => SafeToClean ? "YES" : "REVIEW";
    public string ToolTip => $"{Kind}: {Target}{Environment.NewLine}{Detail}";
}

public sealed record CleanerRiskRow(
    string Severity,
    string Area,
    string Concern,
    string PotentialExploit,
    string RecommendedAction);
