using System;

namespace TGWST.App.Services
{
    /// <summary>
    /// Coordinates long-running heavy operations so only one runs at a time.
    /// Network monitoring workflows are intentionally exempt.
    /// </summary>
    public sealed class OperationCoordinatorService
    {
        private readonly object _sync = new();
        private string? _currentOwner;

        public string? CurrentOwner
        {
            get
            {
                lock (_sync)
                {
                    return _currentOwner;
                }
            }
        }

        public bool TryAcquireHeavy(string operationName, out IDisposable? lease, out string? blockingOwner)
        {
            lease = null;
            blockingOwner = null;

            var normalized = (operationName ?? string.Empty).Trim();
            if (normalized.Length == 0)
            {
                normalized = "unknown";
            }

            lock (_sync)
            {
                if (!string.IsNullOrWhiteSpace(_currentOwner))
                {
                    blockingOwner = _currentOwner;
                    return false;
                }

                _currentOwner = normalized;
                lease = new Lease(this, normalized);
                return true;
            }
        }

        private void Release(string owner)
        {
            lock (_sync)
            {
                if (string.Equals(_currentOwner, owner, StringComparison.Ordinal))
                {
                    _currentOwner = null;
                }
            }
        }

        private sealed class Lease : IDisposable
        {
            private readonly OperationCoordinatorService _parent;
            private readonly string _owner;
            private bool _disposed;

            public Lease(OperationCoordinatorService parent, string owner)
            {
                _parent = parent;
                _owner = owner;
            }

            public void Dispose()
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                _parent.Release(_owner);
            }
        }
    }
}
