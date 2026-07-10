using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using TGWST.App.ViewModels;

namespace TGWST.App.Services;

public sealed class GuiLogService
{
    private const int MaxVisibleEntries = 700;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    private readonly object _writeGate = new();
    private readonly string _logPath;

    public ObservableCollection<SecurityLogEntry> Entries { get; } = new();

    public GuiLogService()
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "TGWST",
            "logs");
        Directory.CreateDirectory(root);
        _logPath = Path.Combine(root, "gui-events.jsonl");
    }

    public void Info(
        string source,
        string message,
        string detail = "",
        string impact = "",
        string recommendedAction = "",
        string linkLabel = "",
        string linkTarget = "") =>
        Append(CyberSeverity.Info, source, message, detail, impact, recommendedAction, linkLabel, linkTarget);

    public void Success(
        string source,
        string message,
        string detail = "",
        string impact = "",
        string recommendedAction = "",
        string linkLabel = "",
        string linkTarget = "") =>
        Append(CyberSeverity.Success, source, message, detail, impact, recommendedAction, linkLabel, linkTarget);

    public void Warning(
        string source,
        string message,
        string detail = "",
        string impact = "",
        string recommendedAction = "",
        string linkLabel = "",
        string linkTarget = "") =>
        Append(CyberSeverity.Warning, source, message, detail, impact, recommendedAction, linkLabel, linkTarget);

    public void Critical(
        string source,
        string message,
        string detail = "",
        string impact = "",
        string recommendedAction = "",
        string linkLabel = "",
        string linkTarget = "") =>
        Append(CyberSeverity.Critical, source, message, detail, impact, recommendedAction, linkLabel, linkTarget);

    public void Append(
        CyberSeverity severity,
        string source,
        string message,
        string detail = "",
        string impact = "",
        string recommendedAction = "",
        string linkLabel = "",
        string linkTarget = "")
    {
        var entry = new SecurityLogEntry(
            DateTimeOffset.Now,
            severity,
            string.IsNullOrWhiteSpace(source) ? "TGWST" : source.Trim(),
            Sanitize(message),
            SanitizeOptional(detail),
            SanitizeOptional(impact),
            SanitizeOptional(recommendedAction),
            SanitizeOptional(linkLabel),
            SanitizeOptional(linkTarget));

        void AddEntry()
        {
            Entries.Add(entry);
            while (Entries.Count > MaxVisibleEntries)
            {
                Entries.RemoveAt(0);
            }
        }

        var dispatcher = System.Windows.Application.Current?.Dispatcher;
        if (dispatcher?.CheckAccess() == true)
        {
            AddEntry();
        }
        else
        {
            _ = dispatcher?.BeginInvoke(AddEntry);
        }

        Persist(entry);
    }

    private void Persist(SecurityLogEntry entry)
    {
        try
        {
            var line = JsonSerializer.Serialize(entry, JsonOptions);
            lock (_writeGate)
            {
                File.AppendAllText(_logPath, line + Environment.NewLine);
            }
        }
        catch
        {
        }
    }

    private static string Sanitize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "-";
        }

        var profileRoot = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var sanitized = string.IsNullOrWhiteSpace(profileRoot)
            ? value
            : value.Replace(profileRoot, "<profile>", StringComparison.OrdinalIgnoreCase);

        return sanitized
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Trim();
    }

    private static string SanitizeOptional(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? string.Empty : Sanitize(value);
    }
}
