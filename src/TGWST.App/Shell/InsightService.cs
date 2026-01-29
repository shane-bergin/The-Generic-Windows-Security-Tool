using System;
using System.Linq;
using System.Threading.Tasks;
using TGWST.Core.Services;

namespace TGWST.App.Shell
{
    public sealed class InsightService
    {
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
            var lines = SplitLines(text);
            var head = string.Join("\n", lines.Take(4));
            var tail = string.Join("\n", lines.Skip(Math.Max(0, lines.Length - 2)));
            return $"Explain (heuristic):\n- Lines: {lines.Length}\n- First lines:\n{head}\n- Last lines:\n{tail}\n";
        }

        private static string BasicSummary(string text)
        {
            var lines = SplitLines(text);
            var head = string.Join("\n", lines.Take(6));
            return $"Summary (heuristic):\n- Lines: {lines.Length}\n- Preview:\n{head}\n";
        }

        private static string[] SplitLines(string text)
        {
            return (text ?? string.Empty)
                .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        }
    }
}
