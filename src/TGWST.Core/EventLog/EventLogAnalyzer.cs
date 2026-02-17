using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.EventLog
{
    public sealed class EventLogAnalyzer
    {
        private static readonly string[] SuspiciousCommandTokens =
        {
            "powershell.exe", "pwsh.exe", "-nop", "-enc", "bitsadmin", "rundll32",
            "wmic", "certutil", "cmd.exe /c", "mshta", "regsvr32"
        };

        public async Task<IReadOnlyList<EventLogFinding>> ScanAsync(TimeSpan lookback, CancellationToken ct = default)
        {
            return await Task.Run(() =>
            {
                var millis = (long)lookback.TotalMilliseconds;
                var queries = new[]
                {
                    ("Security", $"*[System[TimeCreated[timediff(@SystemTime) <= {millis}]]]") ,
                    ("System", $"*[System[TimeCreated[timediff(@SystemTime) <= {millis}]]]") ,
                    ("Application", $"*[System[TimeCreated[timediff(@SystemTime) <= {millis}]]]") ,
                    ("Microsoft-Windows-Windows Defender/Operational", $"*[System[TimeCreated[timediff(@SystemTime) <= {millis}]]]")
                };

                var aggregate = new Dictionary<string, AggregateItem>(StringComparer.OrdinalIgnoreCase);

                foreach (var (logName, xpath) in queries)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var query = new EventLogQuery(logName, PathType.LogName, xpath)
                        {
                            ReverseDirection = true
                        };

                        using var reader = new EventLogReader(query);
                        EventRecord? rec;
                        while ((rec = reader.ReadEvent()) != null)
                        {
                            ct.ThrowIfCancellationRequested();
                            using (rec)
                            {
                                try
                                {
                                    var rule = Classify(logName, rec);
                                    if (rule == null)
                                    {
                                        continue;
                                    }

                                    var message = SafeFormat(rec);
                                    var summary = BuildSummary(rule.Rule, message);
                                    var key = $"{logName}|{rec.Id}|{rec.ProviderName}|{rule.Rule}|{summary}";

                                    if (!aggregate.TryGetValue(key, out var existing))
                                    {
                                        aggregate[key] = new AggregateItem
                                        {
                                            TimeCreated = rec.TimeCreated ?? DateTime.MinValue,
                                            LogName = logName,
                                            EventId = rec.Id,
                                            Source = rec.ProviderName,
                                            Severity = rule.Severity,
                                            Importance = rule.Importance,
                                            IsDrastic = rule.IsDrastic,
                                            Rule = rule.Rule,
                                            Summary = summary,
                                            Purpose = rule.Purpose,
                                            WhyItMatters = rule.WhyItMatters,
                                            Recommendation = rule.Recommendation,
                                            Message = message,
                                            Count = 1
                                        };
                                    }
                                    else
                                    {
                                        existing.Count++;
                                        if ((rec.TimeCreated ?? DateTime.MinValue) > existing.TimeCreated)
                                        {
                                            existing.TimeCreated = rec.TimeCreated ?? DateTime.MinValue;
                                            if (!string.IsNullOrWhiteSpace(message))
                                            {
                                                existing.Message = message;
                                            }
                                        }
                                    }
                                }
                                catch
                                {
                                    // malformed event, skip
                                }
                            }
                        }
                    }
                    catch
                    {
                        // best effort; inaccessible logs are skipped
                    }
                }

                return aggregate.Values
                    .Select(x => new EventLogFinding(
                        TimeCreated: x.TimeCreated,
                        LogName: x.LogName,
                        EventId: x.EventId,
                        Source: x.Source,
                        Severity: x.Severity,
                        Importance: x.Importance,
                        IsDrastic: x.IsDrastic,
                        Rule: x.Rule,
                        Summary: x.Summary,
                        Purpose: x.Purpose,
                        WhyItMatters: x.WhyItMatters,
                        Recommendation: x.Recommendation,
                        Message: x.Message,
                        Count: x.Count))
                    .OrderByDescending(x => x.IsDrastic)
                    .ThenByDescending(x => SeverityRank(x.Severity))
                    .ThenByDescending(x => x.TimeCreated)
                    .ToArray();
            }, ct).ConfigureAwait(false);
        }

        private static RuleMatch? Classify(string logName, EventRecord record)
        {
            var id = record.Id;
            var normalizedLog = logName?.Trim() ?? string.Empty;

            if (normalizedLog.Equals("Security", StringComparison.OrdinalIgnoreCase))
            {
                if (id == 1102)
                {
                    return new RuleMatch(
                        Severity: "High",
                        Importance: "Drastic Issue",
                        IsDrastic: true,
                        Rule: "Security log cleared",
                        Purpose: "Tracks tampering against the security audit trail.",
                        WhyItMatters: "Clearing the Security log can hide attacker actions and erase forensic evidence.",
                        Recommendation: "Immediately investigate the account/context, preserve all remaining logs, and validate host integrity.");
                }

                if (id == 4625)
                {
                    return new RuleMatch(
                        Severity: "Medium",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "Failed logon",
                        Purpose: "Records authentication failures.",
                        WhyItMatters: "Repeated failures may indicate brute-force attempts or credential misuse.",
                        Recommendation: "Review source host/user patterns and lockout policy; escalate if failures spike or target privileged accounts.");
                }

                if (id == 4720)
                {
                    return new RuleMatch(
                        Severity: "Medium",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "User account created",
                        Purpose: "Tracks creation of local/domain user accounts.",
                        WhyItMatters: "Unexpected account creation can indicate persistence or unauthorized admin activity.",
                        Recommendation: "Verify change ticket and creator account; disable unknown accounts and rotate credentials if unauthorized.");
                }

                if (id == 4726)
                {
                    return new RuleMatch(
                        Severity: "Medium",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "User account deleted",
                        Purpose: "Tracks account deletions.",
                        WhyItMatters: "Unexpected deletions can disrupt operations or conceal misuse.",
                        Recommendation: "Validate against admin changes; restore or investigate if deletion was not planned.");
                }

                if (id == 4732 || id == 4728)
                {
                    return new RuleMatch(
                        Severity: "High",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "Privileged group membership change",
                        Purpose: "Audits additions to privileged security groups.",
                        WhyItMatters: "Privilege changes can grant broad control and are common escalation steps.",
                        Recommendation: "Confirm business justification and approver; remove unexpected memberships immediately.");
                }

                if (id == 4688)
                {
                    var message = SafeFormat(record);
                    var lower = message.ToLowerInvariant();
                    if (SuspiciousCommandTokens.Any(t => lower.Contains(t, StringComparison.Ordinal)))
                    {
                        return new RuleMatch(
                            Severity: "High",
                            Importance: "Drastic Issue",
                            IsDrastic: true,
                            Rule: "Suspicious process creation",
                            Purpose: "Detects potentially abusive command execution patterns.",
                            WhyItMatters: "LOLBin/script abuse can indicate active compromise or malware staging.",
                            Recommendation: "Review parent/child process chain, user context, and command line; isolate host if behavior is unexplained.");
                    }
                }

                return null;
            }

            if (normalizedLog.Equals("System", StringComparison.OrdinalIgnoreCase))
            {
                if (id == 7045)
                {
                    return new RuleMatch(
                        Severity: "High",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "Service installed",
                        Purpose: "Tracks new Windows service installation.",
                        WhyItMatters: "New services can be legitimate software installs or persistence mechanisms.",
                        Recommendation: "Validate signer/path and software source; investigate unknown service names or unusual install times.");
                }

                if (id == 7031 || id == 7034)
                {
                    return new RuleMatch(
                        Severity: "Medium",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "Service terminated unexpectedly",
                        Purpose: "Tracks abrupt service failures.",
                        WhyItMatters: "Repeated service crashes may impact stability, availability, or security controls.",
                        Recommendation: "Correlate with recent updates/config changes and inspect service-specific logs.");
                }

                if (id == 41)
                {
                    return new RuleMatch(
                        Severity: "High",
                        Importance: "Drastic Issue",
                        IsDrastic: true,
                        Rule: "Kernel power failure",
                        Purpose: "Indicates improper shutdown/power interruption.",
                        WhyItMatters: "Can cause data corruption and repeated outage symptoms.",
                        Recommendation: "Check PSU/thermal/driver stability and review preceding critical events to identify root cause.");
                }

                if (id == 6008)
                {
                    return new RuleMatch(
                        Severity: "Medium",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "Unexpected shutdown",
                        Purpose: "Records unclean shutdown history.",
                        WhyItMatters: "Frequent unclean shutdowns can indicate instability and risk data integrity.",
                        Recommendation: "Correlate with hardware faults, crashes, and maintenance operations around the timestamp.");
                }

                if (id == 55 || id == 157)
                {
                    return new RuleMatch(
                        Severity: "High",
                        Importance: "Drastic Issue",
                        IsDrastic: true,
                        Rule: "Potential disk corruption/IO issue",
                        Purpose: "Signals file system or storage I/O integrity problems.",
                        WhyItMatters: "Disk integrity issues are a high-risk availability and data-loss condition.",
                        Recommendation: "Run storage diagnostics, inspect SMART/controller health, and back up critical data immediately.");
                }

                return null;
            }

            if (normalizedLog.Equals("Application", StringComparison.OrdinalIgnoreCase))
            {
                if (id == 1000)
                {
                    return new RuleMatch(
                        Severity: "Medium",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "Application crash",
                        Purpose: "Records process-level application failures.",
                        WhyItMatters: "Frequent crashes may indicate instability, incompatible updates, or malicious tampering.",
                        Recommendation: "Review faulting module/version patterns and update or isolate affected software.");
                }

                if (id == 1002)
                {
                    return new RuleMatch(
                        Severity: "Low",
                        Importance: "Typical",
                        IsDrastic: false,
                        Rule: "Application hang",
                        Purpose: "Captures prolonged non-responsive application behavior.",
                        WhyItMatters: "Often a performance or app-quality issue rather than a direct security incident.",
                        Recommendation: "Track recurrence; tune/patch the app if user impact is persistent.");
                }

                if (id == 1026)
                {
                    return new RuleMatch(
                        Severity: "Low",
                        Importance: "Typical",
                        IsDrastic: false,
                        Rule: ".NET runtime exception",
                        Purpose: "Reports managed runtime exceptions from .NET applications.",
                        WhyItMatters: "Usually software quality/dependency issues unless tied to suspicious binaries.",
                        Recommendation: "Assess application impact; investigate only if recurring or linked to untrusted executables.");
                }

                return null;
            }

            if (normalizedLog.Equals("Microsoft-Windows-Windows Defender/Operational", StringComparison.OrdinalIgnoreCase))
            {
                if (id == 1116)
                {
                    return new RuleMatch(
                        Severity: "High",
                        Importance: "Drastic Issue",
                        IsDrastic: true,
                        Rule: "Defender detected malware",
                        Purpose: "Indicates malware or potentially unwanted software detection.",
                        WhyItMatters: "Active threat presence can lead to data loss, lateral movement, or persistence.",
                        Recommendation: "Perform immediate containment and full threat response validation.");
                }

                if (id == 1117 || id == 1118)
                {
                    return new RuleMatch(
                        Severity: "Medium",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "Defender remediation action",
                        Purpose: "Captures remediation or quarantine actions taken by Defender.",
                        WhyItMatters: "Shows threat handling occurred and may require follow-up verification.",
                        Recommendation: "Confirm remediation success and run follow-up scans with updated signatures.");
                }

                if (id == 5001)
                {
                    return new RuleMatch(
                        Severity: "High",
                        Importance: "Drastic Issue",
                        IsDrastic: true,
                        Rule: "Real-time protection disabled",
                        Purpose: "Tracks disabling of real-time malware protection.",
                        WhyItMatters: "Protection gaps significantly increase malware exposure risk.",
                        Recommendation: "Re-enable protection immediately and investigate who/what changed the setting.");
                }

                if (id == 5007)
                {
                    return new RuleMatch(
                        Severity: "Medium",
                        Importance: "Important",
                        IsDrastic: false,
                        Rule: "Defender settings changed",
                        Purpose: "Audits policy/configuration changes in Defender.",
                        WhyItMatters: "Unexpected policy changes can reduce endpoint protection efficacy.",
                        Recommendation: "Validate change source and compare against intended baseline policy.");
                }

                return null;
            }

            return null;
        }

        private static string SafeFormat(EventRecord record)
        {
            try
            {
                return record.FormatDescription() ?? string.Empty;
            }
            catch
            {
                return string.Empty;
            }
        }

        private static string BuildSummary(string rule, string message)
        {
            if (string.IsNullOrWhiteSpace(message))
            {
                return rule;
            }

            var normalized = Regex.Replace(message, @"\s+", " ").Trim();
            if (normalized.Length == 0)
            {
                return rule;
            }

            return normalized.Length <= 180
                ? normalized
                : $"{normalized[..177]}...";
        }

        private static int SeverityRank(string severity)
        {
            return severity switch
            {
                "High" => 3,
                "Medium" => 2,
                "Low" => 1,
                _ => 0
            };
        }

        private sealed class AggregateItem
        {
            public DateTime TimeCreated { get; set; }
            public string LogName { get; set; } = string.Empty;
            public int EventId { get; set; }
            public string? Source { get; set; }
            public string Severity { get; set; } = "Low";
            public string Importance { get; set; } = "Typical";
            public bool IsDrastic { get; set; }
            public string Rule { get; set; } = string.Empty;
            public string Summary { get; set; } = string.Empty;
            public string Purpose { get; set; } = string.Empty;
            public string WhyItMatters { get; set; } = string.Empty;
            public string Recommendation { get; set; } = string.Empty;
            public string? Message { get; set; }
            public int Count { get; set; }
        }

        private sealed record RuleMatch(
            string Severity,
            string Importance,
            bool IsDrastic,
            string Rule,
            string Purpose,
            string WhyItMatters,
            string Recommendation);
    }
}
