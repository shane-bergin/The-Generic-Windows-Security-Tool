using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using dnYara;
using dnYara.Interop;

namespace TGWST.Core.Scan;

public sealed class FileScanEngine
{
    private readonly CompiledRules? _rules;
    private readonly YaraContext? _yaraContext;
    private readonly object _scanLock = new();
    private readonly string? _initError;
    private readonly HashSet<string> _externalRuleNames = new(StringComparer.OrdinalIgnoreCase);

    public FileScanEngine()
    {
        try
        {
            var baseDir = AppContext.BaseDirectory;
            var nativePath = Path.Combine(baseDir, "libyara.dll");
            if (!File.Exists(nativePath))
            {
                _initError = "YARA unavailable: native libyara.dll missing; ensure dnYara.NativePack is copied next to the executable.";
                return;
            }

            _yaraContext = new YaraContext();
            using var compiler = new Compiler();
            var yaraRules = LoadEmbeddedRules("TGWST.Core.Rules.yar");
            compiler.AddRuleString(yaraRules);
            LoadExternalYaraFeeds(compiler);
            _rules = compiler.Compile();
        }
        catch (Exception ex)
        {
            _initError = $"Failed to initialize YARA: {ex.Message}";
        }
    }

    public async Task<IReadOnlyList<ScanResult>> RunFileScanAsync(
        ScanType type,
        string? root = null,
        IProgress<double>? progress = null,
        CancellationToken ct = default)
    {
        if (_rules == null || _yaraContext == null)
        {
            return new[]
            {
                new ScanResult
                {
                    Path = "YARA",
                    Suspicious = false,
                    Reason = $"YARA unavailable: {_initError ?? "failed to load native library"} (ensure libyara.dll is next to TGWST.App.exe)",
                    Engine = "dnYara v2.1.0 (YARA 4.1.1)"
                }
            };
        }

        var results = new ConcurrentBag<ScanResult>();
        var roots = ResolveRoots(type, root).ToArray();
        if (roots.Length == 0) return Array.Empty<ScanResult>();

        var allowedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".jar", ".msi"
        };

        var maxFiles = type == ScanType.Quick ? 500 : 5000;
        var files = EnumerateCandidateFiles(roots, allowedExtensions, maxFiles, ct).ToArray();
        if (files.Length == 0) return Array.Empty<ScanResult>();

        var processed = 0;
        var parallelOptions = new ParallelOptions
        {
            CancellationToken = ct,
            MaxDegreeOfParallelism = Environment.ProcessorCount
        };

        await Parallel.ForEachAsync(files, parallelOptions, (file, token) =>
        {
            try
            {
                List<dnYara.ScanResult> matches;
                lock (_scanLock)
                {
                    var scanner = new Scanner();
                    matches = scanner.ScanFile(file, _rules, YR_SCAN_FLAGS.None);
                }

                var first = matches.FirstOrDefault();
                if (first?.MatchingRule != null)
                {
                    var isExternal = _externalRuleNames.Contains(first.MatchingRule.Identifier);
                    var reason = $"YARA match: {first.MatchingRule.Identifier}";
                    if (isExternal) reason += " (Source: External Feed)";

                    results.Add(new ScanResult
                    {
                        Path = file,
                        Suspicious = true,
                        Reason = reason,
                        YaraRule = first.MatchingRule.Identifier,
                        Engine = "dnYara v2.1.0 (YARA 4.1.1)"
                    });
                }
            }
            catch
            {
                // Silently skip files we can't read (locked, corrupted, etc.)
            }

            var done = Interlocked.Increment(ref processed);
            progress?.Report((double)done / files.Length * 100.0);

            return ValueTask.CompletedTask;
        });

        return results
            .OrderByDescending(r => r.Suspicious)
            .ThenBy(r => r.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IEnumerable<string> ResolveRoots(ScanType type, string? root)
    {
        if (type == ScanType.Custom && !string.IsNullOrWhiteSpace(root) && Directory.Exists(root))
        {
            yield return root;
            yield break;
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);

        if (type == ScanType.Quick)
        {
            var quickFolders = new[]
            {
                Environment.SpecialFolder.Desktop,
                Environment.SpecialFolder.MyDocuments,
                Environment.SpecialFolder.LocalApplicationData
            };

            foreach (var folder in quickFolders)
            {
                var path = Environment.GetFolderPath(folder);
                if (!string.IsNullOrWhiteSpace(path) && Directory.Exists(path))
                    yield return path;
            }
        }

        if (type == ScanType.Full)
        {
            var fixedDrives = DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
                .Select(d => d.RootDirectory.FullName);

            foreach (var drive in fixedDrives)
                yield return drive;
        }
        else
        {
            yield return root ?? userProfile;
        }
    }

    private static IEnumerable<string> EnumerateCandidateFiles(
        IEnumerable<string> roots,
        HashSet<string> allowedExtensions,
        int maxFiles,
        CancellationToken ct)
    {
        var stack = new Stack<string>(roots.Where(Directory.Exists));
        var count = 0;

        while (stack.Count > 0 && count < maxFiles)
        {
            ct.ThrowIfCancellationRequested();

            var current = stack.Pop();

            IEnumerable<string> entries;
            try
            {
                entries = Directory.EnumerateFileSystemEntries(current);
            }
            catch
            {
                continue;
            }

            foreach (var entry in entries)
            {
                ct.ThrowIfCancellationRequested();

                if (Directory.Exists(entry))
                {
                    stack.Push(entry);
                    continue;
                }

                var ext = Path.GetExtension(entry);
                if (allowedExtensions.Contains(ext))
                {
                    yield return entry;
                    count++;
                    if (count >= maxFiles)
                        yield break;
                }
            }
        }
    }

    private static string LoadEmbeddedRules(string resourceName)
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded resource not found: {resourceName}");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private void LoadExternalYaraFeeds(Compiler compiler)
    {
        var files = IocFeedLoader.GetYaraRuleFiles();
        foreach (var file in files)
        {
            try
            {
                compiler.AddRuleFile(file);
                foreach (var name in ParseRuleNames(file))
                    _externalRuleNames.Add(name);
            }
            catch
            {
                // skip bad feed file
            }
        }
    }

    private static IEnumerable<string> ParseRuleNames(string path)
    {
        var names = new List<string>();
        try
        {
            var text = File.ReadAllText(path);
            var regex = new Regex(@"\brule\s+([A-Za-z0-9_]+)", RegexOptions.Compiled);
            foreach (System.Text.RegularExpressions.Match m in regex.Matches(text))
            {
                if (m.Groups.Count > 1)
                    names.Add(m.Groups[1].Value);
            }
        }
        catch
        {
        }
        return names;
    }
}
