using System;
using CommunityToolkit.Mvvm.ComponentModel;
using TGWST.Core.Network;

namespace TGWST.App.ViewModels
{
    public sealed class EndpointFocusItem : ObservableObject
    {
        private string _endpointKey = string.Empty;
        private int _processId;
        private string _processName = "unknown";
        private string _processPath = string.Empty;
        private string _processSigner = string.Empty;
        private string _protocol = "TCP";
        private string _localAddress = string.Empty;
        private int _localPort;
        private string _remoteAddress = string.Empty;
        private int _remotePort;
        private string _remoteHostname = string.Empty;
        private string _remoteCountry = "--";
        private string _actionSymbol = "?";
        private string _actionText = "Unknown";
        private string _riskToken = "--";
        private int _riskScore;
        private string _riskReasons = "none";
        private string _throughputSparkline = "----------";
        private bool _isSelected;
        private long _bytesSent;
        private long _bytesReceived;
        private DateTime _firstSeenLocal = DateTime.MinValue;
        private DateTime _lastSeenLocal = DateTime.MinValue;
        private string _historicalRecordsDisplay = "Historical records: unavailable";
        private string _historicalActionsDisplay = "Historical actions: unavailable";
        private string _recordPullDisplay = "Record pull: live-only";
        private string _dnsEvidenceDisplay = "DNS evidence: unresolved";
        private string _processIdentityDisplay = "Process identity: unavailable";

        public string EndpointKey
        {
            get => _endpointKey;
            private set => SetProperty(ref _endpointKey, value);
        }

        public int ProcessId
        {
            get => _processId;
            private set => SetProperty(ref _processId, value);
        }

        public string ProcessName
        {
            get => _processName;
            private set => SetProperty(ref _processName, value);
        }

        public string ProcessPath
        {
            get => _processPath;
            private set => SetProperty(ref _processPath, value);
        }

        public string ProcessSigner
        {
            get => _processSigner;
            private set => SetProperty(ref _processSigner, value);
        }

        public string Protocol
        {
            get => _protocol;
            private set => SetProperty(ref _protocol, value);
        }

        public string LocalAddress
        {
            get => _localAddress;
            private set => SetProperty(ref _localAddress, value);
        }

        public int LocalPort
        {
            get => _localPort;
            private set => SetProperty(ref _localPort, value);
        }

        public string RemoteAddress
        {
            get => _remoteAddress;
            private set => SetProperty(ref _remoteAddress, value);
        }

        public int RemotePort
        {
            get => _remotePort;
            private set => SetProperty(ref _remotePort, value);
        }

        public string RemoteHostname
        {
            get => _remoteHostname;
            private set => SetProperty(ref _remoteHostname, value);
        }

        public string RemoteCountry
        {
            get => _remoteCountry;
            private set => SetProperty(ref _remoteCountry, value);
        }

        public string ActionSymbol
        {
            get => _actionSymbol;
            private set => SetProperty(ref _actionSymbol, value);
        }

        public string ActionText
        {
            get => _actionText;
            private set => SetProperty(ref _actionText, value);
        }

        public string RiskToken
        {
            get => _riskToken;
            private set => SetProperty(ref _riskToken, value);
        }

        public int RiskScore
        {
            get => _riskScore;
            private set => SetProperty(ref _riskScore, value);
        }

        public string RiskReasons
        {
            get => _riskReasons;
            private set => SetProperty(ref _riskReasons, value);
        }

        public string ThroughputSparkline
        {
            get => _throughputSparkline;
            private set => SetProperty(ref _throughputSparkline, value);
        }

        public bool IsSelected
        {
            get => _isSelected;
            set => SetProperty(ref _isSelected, value);
        }

        public long BytesSent
        {
            get => _bytesSent;
            private set => SetProperty(ref _bytesSent, value);
        }

        public long BytesReceived
        {
            get => _bytesReceived;
            private set => SetProperty(ref _bytesReceived, value);
        }

        public DateTime FirstSeenLocal
        {
            get => _firstSeenLocal;
            private set => SetProperty(ref _firstSeenLocal, value);
        }

        public DateTime LastSeenLocal
        {
            get => _lastSeenLocal;
            private set => SetProperty(ref _lastSeenLocal, value);
        }

        public string HistoricalRecordsDisplay
        {
            get => _historicalRecordsDisplay;
            private set => SetProperty(ref _historicalRecordsDisplay, value);
        }

        public string HistoricalActionsDisplay
        {
            get => _historicalActionsDisplay;
            private set => SetProperty(ref _historicalActionsDisplay, value);
        }

        public string RecordPullDisplay
        {
            get => _recordPullDisplay;
            private set => SetProperty(ref _recordPullDisplay, value);
        }

        public string DnsEvidenceDisplay
        {
            get => _dnsEvidenceDisplay;
            private set => SetProperty(ref _dnsEvidenceDisplay, value);
        }

        public string ProcessIdentityDisplay
        {
            get => _processIdentityDisplay;
            private set => SetProperty(ref _processIdentityDisplay, value);
        }

        public long TotalBytes => BytesSent + BytesReceived;
        public string TotalBytesDisplay => FlowRecord.FormatBytes(TotalBytes);
        public string BytesSentDisplay => FlowRecord.FormatBytes(BytesSent);
        public string BytesReceivedDisplay => FlowRecord.FormatBytes(BytesReceived);

        public string EndpointDisplay => string.IsNullOrWhiteSpace(RemoteHostname)
            ? $"{RemoteAddress}:{RemotePort}"
            : $"{RemoteHostname}:{RemotePort}";

        public string EndpointSubline => $"{ProcessName}  pid:{ProcessId}  {Protocol}  {ActionText}/{RiskToken}";

        public string DnsHostDisplay => string.IsNullOrWhiteSpace(RemoteHostname)
            ? "(unresolved)"
            : RemoteHostname;

        public string DnsStatusDisplay => string.IsNullOrWhiteSpace(RemoteHostname)
            ? "No hostname captured from DNS telemetry for this flow."
            : "Hostname captured via native Windows DNS telemetry.";

        public string RiskTag
        {
            get
            {
                return RiskToken.ToUpperInvariant() switch
                {
                    "HIGH" => "high",
                    "MED" => "med",
                    "LOW" => "low",
                    _ => "unknown"
                };
            }
        }

        public string FlowDurationDisplay
        {
            get
            {
                if (LastSeenLocal <= FirstSeenLocal)
                {
                    return "00:00:00";
                }

                return (LastSeenLocal - FirstSeenLocal).ToString(@"hh\:mm\:ss");
            }
        }

        public string LastSeenDisplay => LastSeenLocal == DateTime.MinValue ? "-" : LastSeenLocal.ToString("T");
        public string FirstSeenDisplay => FirstSeenLocal == DateTime.MinValue ? "-" : FirstSeenLocal.ToString("T");

        public static EndpointFocusItem FromSnapshot(EndpointFocusSnapshot snapshot)
        {
            var item = new EndpointFocusItem();
            item.Update(snapshot);
            return item;
        }

        public void Update(EndpointFocusSnapshot snapshot)
        {
            EndpointKey = snapshot.EndpointKey;
            ProcessId = snapshot.ProcessId;
            ProcessName = snapshot.ProcessName;
            ProcessPath = snapshot.ProcessPath;
            ProcessSigner = snapshot.ProcessSigner;
            Protocol = snapshot.Protocol;
            LocalAddress = snapshot.LocalAddress;
            LocalPort = snapshot.LocalPort;
            RemoteAddress = snapshot.RemoteAddress;
            RemotePort = snapshot.RemotePort;
            RemoteHostname = snapshot.RemoteHostname;
            RemoteCountry = snapshot.RemoteCountry;
            ActionSymbol = snapshot.ActionSymbol;
            ActionText = snapshot.ActionText;
            RiskToken = snapshot.RiskToken;
            RiskScore = snapshot.RiskScore;
            RiskReasons = snapshot.RiskReasons;
            ThroughputSparkline = string.IsNullOrWhiteSpace(snapshot.ThroughputSparkline)
                ? "----------"
                : snapshot.ThroughputSparkline;
            BytesSent = snapshot.BytesSent;
            BytesReceived = snapshot.BytesReceived;
            FirstSeenLocal = snapshot.FirstSeenLocal;
            LastSeenLocal = snapshot.LastSeenLocal;

            RaiseDerivedPropertyChanges();
        }

        public void SetInspectionContext(EndpointInspectionContext? context)
        {
            if (context == null)
            {
                return;
            }

            HistoricalRecordsDisplay = string.IsNullOrWhiteSpace(context.HistoricalRecords)
                ? "Historical records: unavailable"
                : context.HistoricalRecords;
            HistoricalActionsDisplay = string.IsNullOrWhiteSpace(context.HistoricalActions)
                ? "Historical actions: unavailable"
                : context.HistoricalActions;
            RecordPullDisplay = string.IsNullOrWhiteSpace(context.RecordPull)
                ? "Record pull: live-only"
                : context.RecordPull;
            DnsEvidenceDisplay = string.IsNullOrWhiteSpace(context.DnsEvidence)
                ? "DNS evidence: unresolved"
                : context.DnsEvidence;
            ProcessIdentityDisplay = string.IsNullOrWhiteSpace(context.ProcessIdentity)
                ? "Process identity: unavailable"
                : context.ProcessIdentity;
        }

        private void RaiseDerivedPropertyChanges()
        {
            OnPropertyChanged(nameof(TotalBytes));
            OnPropertyChanged(nameof(TotalBytesDisplay));
            OnPropertyChanged(nameof(BytesSentDisplay));
            OnPropertyChanged(nameof(BytesReceivedDisplay));
            OnPropertyChanged(nameof(EndpointDisplay));
            OnPropertyChanged(nameof(EndpointSubline));
            OnPropertyChanged(nameof(DnsHostDisplay));
            OnPropertyChanged(nameof(DnsStatusDisplay));
            OnPropertyChanged(nameof(RiskTag));
            OnPropertyChanged(nameof(FlowDurationDisplay));
            OnPropertyChanged(nameof(LastSeenDisplay));
            OnPropertyChanged(nameof(FirstSeenDisplay));
        }
    }

    public sealed record EndpointFocusSnapshot(
        string EndpointKey,
        int ProcessId,
        string ProcessName,
        string ProcessPath,
        string ProcessSigner,
        string Protocol,
        string LocalAddress,
        int LocalPort,
        string RemoteAddress,
        int RemotePort,
        string RemoteHostname,
        string RemoteCountry,
        string ActionSymbol,
        string ActionText,
        string RiskToken,
        int RiskScore,
        string RiskReasons,
        string ThroughputSparkline,
        long BytesSent,
        long BytesReceived,
        DateTime FirstSeenLocal,
        DateTime LastSeenLocal);

    public sealed record EndpointInspectionContext(
        string HistoricalRecords,
        string HistoricalActions,
        string RecordPull,
        string DnsEvidence,
        string ProcessIdentity);
}
