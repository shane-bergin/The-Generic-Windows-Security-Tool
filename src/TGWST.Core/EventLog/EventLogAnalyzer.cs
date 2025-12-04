using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace TGWST.Core.EventLog;

public sealed class EventLogAnalyzer
{
    private static readonly string[] SuspiciousCommandTokens =
    {
        "powershell.exe", "-nop", "-enc", "bitsadmin", "rundll32", "wmic", "certutil", "cmd.exe /c"
    };

    public async Task<IReadOnlyList<EventLogFinding>> ScanAsync(TimeSpan lookback, CancellationToken ct = default)
    {
        return await Task.Run(() =>
        {
            var findings = new List<EventLogFinding>();
            var millis = (long)lookback.TotalMilliseconds;
            var queries = new[]
            {
                ("Security", $"*[System[TimeCreated[timediff(@SystemTime) <= {millis}]]]"),
                ("System", $"*[System[TimeCreated[timediff(@SystemTime) <= {millis}]]]")
            };

            foreach (var (log, xpath) in queries)
            {
                try
                {
                    var query = new EventLogQuery(log, PathType.LogName, xpath)
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
                                var rule = Classify(rec);
                                if (rule == null) continue;

                                var msg = SafeFormat(rec);
                                findings.Add(new EventLogFinding(
                                    rec.TimeCreated ?? DateTime.MinValue,
                                    rec.Id,
                                    rec.ProviderName,
                                    rec.LevelDisplayName,
                                    rule,
                                    msg));
                            }
                            catch
                            {
                                // skip malformed
                            }
                        }
                    }
                }
                catch
                {
                    // ignore log access issues
                }
            }

            return findings
                .OrderByDescending(f => f.TimeCreated)
                .ToArray();
        }, ct).ConfigureAwait(false);
    }

    private static string SafeFormat(EventRecord rec)
    {
        try
        {
            return rec.FormatDescription() ?? "";
        }
        catch
        {
            return "";
        }
    }

    private static string? Classify(EventRecord rec)
    {
        var id = rec.Id;
        switch (id)
        {
            case 1102: return "Security log cleared";
            case 4625: return "Failed logon";
            case 4720: return "User account created";
            case 7045: return "Service installed";
        }

        if (id == 4688)
        {
            var msg = SafeFormat(rec);
            if (string.IsNullOrEmpty(msg)) return null;
            var lower = msg.ToLowerInvariant();
            if (SuspiciousCommandTokens.Any(t => lower.Contains(t)))
                return "Suspicious process creation";
        }

        return null;
    }
}
