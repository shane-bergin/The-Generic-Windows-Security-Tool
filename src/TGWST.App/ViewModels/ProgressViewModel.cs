using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using TGWST.App.Shell;

namespace TGWST.App.ViewModels
{
    public sealed class ProgressViewModel : ObservableObject
    {
        public ObservableCollection<OutputBlock> Output { get; } = new();
        public ObservableCollection<EndpointFocusItem> InteractiveEndpoints { get; } = new();

        public bool HasInteractiveEndpoints => InteractiveEndpoints.Count > 0;
        public string SelectedEndpointKey => _selectedEndpointKey ?? string.Empty;

        private string _title = "Task Output";
        public string Title
        {
            get => _title;
            set => SetProperty(ref _title, value);
        }

        private string _status = "Running...";
        public string Status
        {
            get => _status;
            set => SetProperty(ref _status, value);
        }

        private bool _acronymsExpanded;
        private string _endpointFilter = string.Empty;
        private string? _selectedEndpointKey;
        private readonly Dictionary<string, EndpointFocusItem> _allInteractiveEndpoints = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> _interactiveOrder = new();

        public string EndpointFilter
        {
            get => _endpointFilter;
            set
            {
                var normalized = (value ?? string.Empty).Trim();
                if (!SetProperty(ref _endpointFilter, normalized))
                {
                    return;
                }

                RefreshInteractiveEndpointView();
            }
        }

        public void Append(string text)
        {
            var display = _acronymsExpanded ? AcronymExpander.Expand(text) : text;
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher?.CheckAccess() == true)
            {
                Output.Add(new OutputBlock(text, display, _acronymsExpanded));
                return;
            }

            _ = dispatcher?.BeginInvoke(new Action(() =>
                Output.Add(new OutputBlock(text, display, _acronymsExpanded))));
        }

        public void ClearOutput()
        {
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            if (dispatcher?.CheckAccess() == true)
            {
                Output.Clear();
                return;
            }

            _ = dispatcher?.BeginInvoke(new Action(Output.Clear));
        }

        public void SetInteractiveEndpoints(IReadOnlyList<EndpointFocusSnapshot> snapshots)
        {
            var safeSnapshots = snapshots ?? Array.Empty<EndpointFocusSnapshot>();
            var dispatcher = System.Windows.Application.Current?.Dispatcher;

            void Apply()
            {
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _interactiveOrder.Clear();

                foreach (var snapshot in safeSnapshots)
                {
                    if (string.IsNullOrWhiteSpace(snapshot.EndpointKey))
                    {
                        continue;
                    }

                    if (!_allInteractiveEndpoints.TryGetValue(snapshot.EndpointKey, out var item))
                    {
                        item = EndpointFocusItem.FromSnapshot(snapshot);
                        _allInteractiveEndpoints[snapshot.EndpointKey] = item;
                    }
                    else
                    {
                        item.Update(snapshot);
                    }

                    _interactiveOrder.Add(snapshot.EndpointKey);
                    seen.Add(snapshot.EndpointKey);
                }

                var staleKeys = _allInteractiveEndpoints.Keys
                    .Where(key => !seen.Contains(key))
                    .ToArray();
                foreach (var stale in staleKeys)
                {
                    _allInteractiveEndpoints.Remove(stale);
                }

                if (!string.IsNullOrWhiteSpace(_selectedEndpointKey) && !_allInteractiveEndpoints.ContainsKey(_selectedEndpointKey))
                {
                    _selectedEndpointKey = null;
                }

                if (string.IsNullOrWhiteSpace(_selectedEndpointKey) && _interactiveOrder.Count > 0)
                {
                    _selectedEndpointKey = _interactiveOrder[0];
                }

                RefreshInteractiveEndpointView();
            }

            if (dispatcher?.CheckAccess() == true)
            {
                Apply();
                return;
            }

            _ = dispatcher?.BeginInvoke(new Action(Apply));
        }

        public void ClearInteractiveEndpoints()
        {
            var dispatcher = System.Windows.Application.Current?.Dispatcher;

            void Apply()
            {
                _allInteractiveEndpoints.Clear();
                _interactiveOrder.Clear();
                InteractiveEndpoints.Clear();
                _selectedEndpointKey = null;
                OnPropertyChanged(nameof(HasInteractiveEndpoints));
                OnPropertyChanged(nameof(SelectedEndpointKey));
            }

            if (dispatcher?.CheckAccess() == true)
            {
                Apply();
                return;
            }

            _ = dispatcher?.BeginInvoke(new Action(Apply));
        }

        public void SelectInteractiveEndpoint(string endpointKey)
        {
            if (string.IsNullOrWhiteSpace(endpointKey))
            {
                return;
            }

            var dispatcher = System.Windows.Application.Current?.Dispatcher;

            void Apply()
            {
                _selectedEndpointKey = endpointKey.Trim();
                foreach (var item in _allInteractiveEndpoints.Values)
                {
                    item.IsSelected = string.Equals(item.EndpointKey, _selectedEndpointKey, StringComparison.OrdinalIgnoreCase);
                }

                OnPropertyChanged(nameof(SelectedEndpointKey));
                RefreshInteractiveEndpointView();
            }

            if (dispatcher?.CheckAccess() == true)
            {
                Apply();
                return;
            }

            _ = dispatcher?.BeginInvoke(new Action(Apply));
        }

        private void RefreshInteractiveEndpointView()
        {
            var dispatcher = System.Windows.Application.Current?.Dispatcher;

            void Apply()
            {
                var filter = (_endpointFilter ?? string.Empty).Trim();
                var filtered = new List<EndpointFocusItem>();

                foreach (var key in _interactiveOrder)
                {
                    if (!_allInteractiveEndpoints.TryGetValue(key, out var item))
                    {
                        continue;
                    }

                    item.IsSelected = !string.IsNullOrWhiteSpace(_selectedEndpointKey) &&
                                      string.Equals(item.EndpointKey, _selectedEndpointKey, StringComparison.OrdinalIgnoreCase);

                    if (filter.Length > 0 && !MatchesEndpointFilter(item, filter))
                    {
                        continue;
                    }

                    filtered.Add(item);
                }

                InteractiveEndpoints.Clear();
                foreach (var item in filtered)
                {
                    InteractiveEndpoints.Add(item);
                }

                OnPropertyChanged(nameof(HasInteractiveEndpoints));
                OnPropertyChanged(nameof(SelectedEndpointKey));
            }

            if (dispatcher?.CheckAccess() == true)
            {
                Apply();
                return;
            }

            _ = dispatcher?.BeginInvoke(new Action(Apply));
        }

        private static bool MatchesEndpointFilter(EndpointFocusItem item, string filter)
        {
            return item.ProcessName.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                   item.RemoteAddress.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                   item.RemoteHostname.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                   item.EndpointDisplay.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                   item.ProcessId.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase);
        }

        public void SetAcronymMode(bool expanded)
        {
            if (_acronymsExpanded == expanded) return;
            _acronymsExpanded = expanded;
            var dispatcher = System.Windows.Application.Current?.Dispatcher;
            void Apply()
            {
                foreach (var block in Output)
                {
                    block.DisplayText = expanded ? AcronymExpander.Expand(block.RawText) : block.RawText;
                    block.IsAcronymsExpanded = expanded;
                }
            }

            if (dispatcher?.CheckAccess() == true)
            {
                Apply();
                return;
            }

            dispatcher?.Invoke(Apply);
        }
    }
}
