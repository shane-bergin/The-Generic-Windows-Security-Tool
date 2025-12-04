using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using dnYara;
using dnYara.Interop;
using TGWST.Core.Feeds;

namespace TGWST.Core.Scan;

public sealed class FileScanEngine
{
    private CompiledRules? _rules;
    private readonly YaraContext? _yaraContext;
    private readonly object _scanLock = new();
    private string? _initError;
    private readonly HashSet<string> _externalRuleNames = new(StringComparer.OrdinalIgnoreCase);
    private string _externalKey = "";

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
            _rules = null;
            _externalKey = "";
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
        await EnsureRulesAsync(ct).ConfigureAwait(false);

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

        var filenameLookup = BuildIocFilenameLookup(FeedManager.IocBundles);
        var hashLookup = BuildIocHashLookup(FeedManager.IocBundles);
        var hashCheckEnabled = hashLookup.Count > 0;

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

                    var fileName = Path.GetFileName(file);
                    var ioc = TryMatchIoc(file, fileName, filenameLookup, hashLookup, hashCheckEnabled);

                    var source = isExternal ? "External Feed" : "Embedded";
                    if (ioc != null) source = "External Feed (IOC)";

                    results.Add(new ScanResult
                    {
                        Path = file,
                        Suspicious = true,
                        Reason = reason,
                        YaraRule = first.MatchingRule.Identifier,
                        Engine = "dnYara v2.1.0 (YARA 4.1.1)",
                        Source = source,
                        ThreatFamily = ioc?.Bundle.Family,
                        IndicatorType = ioc?.IndicatorType,
                        IndicatorValue = ioc?.IndicatorValue
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

    private async Task EnsureRulesAsync(CancellationToken ct)
    {
        if (_yaraContext == null) return;

        var external = FeedManager.YaraRuleFiles.ToArray();
        var key = string.Join("|", external.OrderBy(f => f, StringComparer.OrdinalIgnoreCase));

        lock (_scanLock)
        {
            if (_rules != null && key.Equals(_externalKey, StringComparison.OrdinalIgnoreCase))
                return;
        }

        try
        {
            var compiled = await Task.Run(async () =>
            {
                using var compiler = new Compiler();
                var yaraRules = LoadEmbeddedRules("TGWST.Core.Rules.yar");
                compiler.AddRuleString(yaraRules);
                var externalResult = await FeedLoader.LoadExternalYaraRulesAsync(compiler, external, ct).ConfigureAwait(false);
                var compiledRules = compiler.Compile();
                return (compiledRules, externalResult);
            }, ct).ConfigureAwait(false);

            lock (_scanLock)
            {
                _rules = compiled.compiledRules;
                _externalRuleNames.Clear();
                foreach (var name in compiled.externalResult.RuleNames)
                    _externalRuleNames.Add(name);
                _externalKey = key;
                _initError = null;
            }
        }
        catch (Exception ex)
        {
            lock (_scanLock)
            {
                _rules = null;
                _externalRuleNames.Clear();
                _initError = $"Failed to initialize YARA: {ex.Message}";
            }
        }
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

    private static Dictionary<string, TGWST.Core.Feeds.IocBundle> BuildIocFilenameLookup(IReadOnlyList<TGWST.Core.Feeds.IocBundle> bundles)
    {
        var map = new Dictionary<string, TGWST.Core.Feeds.IocBundle>(StringComparer.OrdinalIgnoreCase);
        foreach (var bundle in bundles)
        {
            if (bundle.Filenames == null) continue;
            foreach (var name in bundle.Filenames.Where(n => !string.IsNullOrWhiteSpace(n)))
                map[name] = bundle;
        }
        return map;
    }

    private static Dictionary<string, TGWST.Core.Feeds.IocBundle> BuildIocHashLookup(IReadOnlyList<TGWST.Core.Feeds.IocBundle> bundles)
    {
        var map = new Dictionary<string, TGWST.Core.Feeds.IocBundle>(StringComparer.OrdinalIgnoreCase);
        foreach (var bundle in bundles)
        {
            if (string.IsNullOrWhiteSpace(bundle.SampleHash)) continue;
            map[bundle.SampleHash.Trim()] = bundle;
        }
        return map;
    }

    private sealed record IocMatch(TGWST.Core.Feeds.IocBundle Bundle, string IndicatorType, string IndicatorValue);

    private static IocMatch? TryMatchIoc(
        string filePath,
        string? fileName,
        Dictionary<string, TGWST.Core.Feeds.IocBundle> filenameLookup,
        Dictionary<string, TGWST.Core.Feeds.IocBundle> hashLookup,
        bool hashCheckEnabled)
    {
        if (!string.IsNullOrWhiteSpace(fileName) &&
            filenameLookup.TryGetValue(fileName, out var bundleFromName))
        {
            return new IocMatch(bundleFromName, "filename", fileName);
        }

        if (hashCheckEnabled)
        {
            var hash = ComputeSha256(filePath);
            if (!string.IsNullOrWhiteSpace(hash) && hashLookup.TryGetValue(hash, out var bundleFromHash))
            {
                return new IocMatch(bundleFromHash, "sha256", hash);
            }
        }

        return null;
    }

    private static string? ComputeSha256(string path)
    {
        try
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(path);
            var hash = sha.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return null;
        }
    }
}
