using System;
using System.IO;

namespace TGWST.Core.Policies
{
    public sealed class PolicySnapshotStore
    {
        private readonly string _root;

        public PolicySnapshotStore(string? baseDirectory = null)
        {
            _root = baseDirectory ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "TGWST",
                "Snapshots");
            Directory.CreateDirectory(_root);
        }

        public string CreateSnapshotPath(string kind)
        {
            var dir = GetKindDirectory(kind);
            Directory.CreateDirectory(dir);
            var fileName = $"{DateTimeOffset.UtcNow:yyyyMMdd-HHmmssfff}.json";
            return Path.Combine(dir, fileName);
        }

        public void SetLatest(string kind, string path)
        {
            var dir = GetKindDirectory(kind);
            Directory.CreateDirectory(dir);
            var latestPath = Path.Combine(dir, "latest.txt");
            File.WriteAllText(latestPath, path);
        }

        public string? GetLatest(string kind)
        {
            var latestPath = Path.Combine(GetKindDirectory(kind), "latest.txt");
            if (!File.Exists(latestPath)) return null;
            var value = File.ReadAllText(latestPath).Trim();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        private string GetKindDirectory(string kind)
        {
            var safe = string.IsNullOrWhiteSpace(kind)
                ? "Unknown"
                : kind.Trim().Replace(" ", "_", StringComparison.OrdinalIgnoreCase);
            return Path.Combine(_root, safe);
        }
    }
}
