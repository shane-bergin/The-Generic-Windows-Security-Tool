using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using TGWST.Core.Services;

namespace TGWST.App.Shell
{
    public sealed class InsightService
    {
        private static readonly string[] ErrorTokens =
        {
            "error", "failed", "unable", "unavailable", "not installed",
            "missing", "denied", "timeout", "timed out", "exception"
        };

        private static readonly string[] WarningTokens =
        {
            "warning", "degraded", "partial", "fallback", "retry"
        };

        private static readonly Regex SpacedTokenRegex =
            new(@"\b(?:[A-Za-z0-9]\s+){2,}[A-Za-z0-9]\b", RegexOptions.Compiled);

        private LocalIntelligence? _local;
        private bool _localInitAttempted;

        public Task<string> ExplainAsync(string text)
        {
            var prompt = BuildPrompt("Explain the following security tool output in plain language. Highlight risks or next steps.", text);
            return AnalyzeAsync(prompt, fallback: BasicExplain(text));
        }

        public Task<string> SummarizeAsync(string text)
        {
            var prompt = BuildPrompt("Summarize the key points and any warnings from the following output.", text);
            return AnalyzeAsync(prompt, fallback: BasicSummary(text));
        }

        private async Task<string> AnalyzeAsync(string prompt, string fallback)
        {
            var model = TryGetLocal();
            if (model == null)
            {
                return fallback;
            }

            try
            {
                return await Task.Run(() => model.Analyze(prompt));
            }
            catch
            {
                return fallback;
            }
        }

        private LocalIntelligence? TryGetLocal()
        {
            if (_local != null)
            {
                return _local;
            }

            if (_localInitAttempted)
            {
                return null;
            }

            _localInitAttempted = true;
            try
            {
                _local = new LocalIntelligence();
            }
            catch
            {
                _local = null;
            }

            return _local;
        }

        private static string BuildPrompt(string instruction, string text)
        {
            var trimmed = text ?? string.Empty;
            if (trimmed.Length > 4000)
            {
                trimmed = trimmed.Substring(0, 4000) + "\n... [truncated]";
            }

            return $"{instruction}\n\n---\n{trimmed}\n---";
        }

        private static string BasicExplain(string text)
        {
            var lines = SplitLines(text)
                .Select(NormalizeLine)
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .ToArray();

            var findings = ExtractFindings(lines, maxItems: 4);
            var nextSteps = SuggestNextSteps(lines, maxItems: 3);

            var sb = new StringBuilder(512);
            sb.AppendLine("Explain (rule-based):");
            sb.AppendLine($"- Lines analyzed: {lines.Length}");

            if (findings.Count > 0)
            {
                sb.AppendLine("- Key observations:");
                foreach (var finding in findings)
                {
                    sb.Append("- ").AppendLine(finding);
                }
            }
            else
            {
                sb.AppendLine("- No explicit errors/warnings detected.");
            }

            if (nextSteps.Count > 0)
            {
                sb.AppendLine("- Next commands:");
                foreach (var step in nextSteps)
                {
                    sb.Append("- ").AppendLine(step);
                }
            }

            return sb.ToString();
        }

        private static string BasicSummary(string text)
        {
            var lines = SplitLines(text)
                .Select(NormalizeLine)
                .Where(l => !string.IsNullOrWhiteSpace(l))
                .ToArray();

            var findings = ExtractFindings(lines, maxItems: 6);
            var informative = lines
                .Where(IsInformativeLine)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(4)
                .Select(l => TrimForDisplay(l, 120))
                .ToArray();
            var nextSteps = SuggestNextSteps(lines, maxItems: 4);

            var sb = new StringBuilder(768);
            sb.AppendLine("Summary (rule-based):");
            sb.AppendLine($"- Lines analyzed: {lines.Length}");

            if (findings.Count > 0)
            {
                sb.AppendLine("- Findings:");
                foreach (var finding in findings)
                {
                    sb.Append("- ").AppendLine(finding);
                }
            }
            else if (informative.Length > 0)
            {
                sb.AppendLine("- Signals:");
                foreach (var line in informative)
                {
                    sb.Append("- ").AppendLine(line);
                }
            }
            else
            {
                sb.AppendLine("- No meaningful signals found.");
            }

            if (nextSteps.Count > 0)
            {
                sb.AppendLine("- Recommended next steps:");
                foreach (var step in nextSteps)
                {
                    sb.Append("- ").AppendLine(step);
                }
            }

            return sb.ToString();
        }

        private static string[] SplitLines(string text)
        {
            return (text ?? string.Empty)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }

        private static string NormalizeLine(string line)
        {
            var value = (line ?? string.Empty).Trim();
            if (value.Length == 0)
            {
                return string.Empty;
            }

            value = SpacedTokenRegex.Replace(value, match => match.Value.Replace(" ", string.Empty));
            value = Regex.Replace(value, @"\s{2,}", " ");
            return value;
        }

        private static List<string> ExtractFindings(IReadOnlyList<string> lines, int maxItems)
        {
            var findings = new List<string>(maxItems);
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in lines)
            {
                var lower = line.ToLowerInvariant();
                var severity = GetSeverity(lower);
                if (severity == null)
                {
                    continue;
                }

                var normalized = TrimForDisplay(line, 140);
                if (!seen.Add(normalized))
                {
                    continue;
                }

                findings.Add($"{severity} {normalized}");
                if (findings.Count >= maxItems)
                {
                    break;
                }
            }

            return findings;
        }

        private static string? GetSeverity(string lowerLine)
        {
            if (ErrorTokens.Any(token => lowerLine.Contains(token, StringComparison.Ordinal)))
            {
                return "[ERROR]";
            }

            if (WarningTokens.Any(token => lowerLine.Contains(token, StringComparison.Ordinal)))
            {
                return "[WARN]";
            }

            return null;
        }

        private static bool IsInformativeLine(string line)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                return false;
            }

            return line.Any(char.IsLetterOrDigit);
        }

        private static List<string> SuggestNextSteps(IReadOnlyList<string> lines, int maxItems)
        {
            var joined = string.Join('\n', lines).ToLowerInvariant();
            var steps = new List<string>(maxItems);

            void Add(string step)
            {
                if (steps.Count < maxItems && !steps.Contains(step, StringComparer.OrdinalIgnoreCase))
                {
                    steps.Add(step);
                }
            }

            if (joined.Contains("unable to execute bash", StringComparison.Ordinal) ||
                joined.Contains("linux analytics: unavailable", StringComparison.Ordinal))
            {
                Add("Run: network hybrid status");
                var distro = TryExtractDistro(lines);
                if (!string.IsNullOrWhiteSpace(distro))
                {
                    Add($"Run: network hybrid distro {distro}");
                }
                Add("Run: network setup");
            }

            if (joined.Contains("pi-hole not installed", StringComparison.Ordinal) ||
                joined.Contains("pihole cli is not installed", StringComparison.Ordinal))
            {
                Add("Install Pi-hole in your selected WSL distro");
                Add("Run: network pihole status");
            }

            if (joined.Contains("unknown command", StringComparison.Ordinal))
            {
                Add("Run: help");
            }

            if (steps.Count == 0)
            {
                Add("Run: network board");
                Add("Run: network setup");
            }

            return steps;
        }

        private static string? TryExtractDistro(IReadOnlyList<string> lines)
        {
            foreach (var line in lines)
            {
                var lower = line.ToLowerInvariant();
                if (!lower.Contains("available distros", StringComparison.Ordinal) &&
                    !lower.Contains("distro selected", StringComparison.Ordinal))
                {
                    continue;
                }

                var idx = line.IndexOf(':');
                if (idx < 0 || idx >= line.Length - 1)
                {
                    continue;
                }

                var candidate = line[(idx + 1)..].Trim().Trim(',');
                if (string.IsNullOrWhiteSpace(candidate))
                {
                    continue;
                }

                var first = candidate.Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .FirstOrDefault(s => s.Length > 0);

                if (!string.IsNullOrWhiteSpace(first))
                {
                    return first;
                }
            }

            return null;
        }

        private static string TrimForDisplay(string value, int maxLength)
        {
            if (value.Length <= maxLength)
            {
                return value;
            }

            return value[..maxLength].TrimEnd() + "...";
        }
    }
}
