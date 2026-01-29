using System;
using System.IO;
using System.Text.Json;

namespace TGWST.Core.Audit
{
    public sealed record AuditEvent(
        DateTimeOffset TimestampUtc,
        string Action,
        string Details,
        string? CorrelationId,
        string Actor,
        bool Privileged);

    public sealed class AuditLogService
    {
        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            WriteIndented = false
        };

        private readonly string _logPath;

        public AuditLogService(string? baseDirectory = null)
        {
            var root = baseDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST",
                "Audit");
            Directory.CreateDirectory(root);
            _logPath = Path.Combine(root, "audit.jsonl");
        }

        public void Write(string action, string details, string? correlationId = null, bool privileged = false)
        {
            var entry = new AuditEvent(
                TimestampUtc: DateTimeOffset.UtcNow,
                Action: action,
                Details: details,
                CorrelationId: correlationId,
                Actor: Environment.UserName,
                Privileged: privileged);

            var line = JsonSerializer.Serialize(entry, JsonOptions);
            File.AppendAllText(_logPath, line + Environment.NewLine);
        }
    }
}
