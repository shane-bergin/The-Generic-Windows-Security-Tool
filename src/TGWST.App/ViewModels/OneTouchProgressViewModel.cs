using System;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;

namespace TGWST.App.ViewModels;

public sealed class OneTouchProgressViewModel : ObservableObject
{
    private string _currentOperation = "preparing";
    private string _result = "waiting for action result";
    private int _percent;
    private bool _isRunning = true;

    public OneTouchProgressViewModel(string actionName, IReadOnlyList<string> steps)
    {
        ActionName = actionName;
        WindowTitle = $"TGWST :: {actionName}";
        StartedAt = DateTimeOffset.Now;

        var index = 1;
        foreach (var step in steps)
        {
            Steps.Add(new OneTouchProgressStepViewModel(index++, step));
        }
    }

    public string ActionName { get; }

    public string WindowTitle { get; }

    public DateTimeOffset StartedAt { get; }

    public ObservableCollection<OneTouchProgressStepViewModel> Steps { get; } = new();

    public string CurrentOperation
    {
        get => _currentOperation;
        private set => SetProperty(ref _currentOperation, value);
    }

    public string Result
    {
        get => _result;
        private set => SetProperty(ref _result, value);
    }

    public int Percent
    {
        get => _percent;
        private set
        {
            if (SetProperty(ref _percent, Math.Clamp(value, 0, 100)))
            {
                OnPropertyChanged(nameof(PercentText));
            }
        }
    }

    public string PercentText => IsRunning ? "RUNNING" : $"{Percent}%";

    public bool IsRunning
    {
        get => _isRunning;
        private set
        {
            if (SetProperty(ref _isRunning, value))
            {
                OnPropertyChanged(nameof(CanClose));
                OnPropertyChanged(nameof(PercentText));
            }
        }
    }

    public bool CanClose => !IsRunning;

    public void MarkCurrent(int stepIndex, int percent, string detail)
    {
        Percent = percent;
        CurrentOperation = detail;

        for (var i = 0; i < Steps.Count; i++)
        {
            if (i < stepIndex)
            {
                Steps[i].MarkComplete();
            }
            else if (i == stepIndex)
            {
                Steps[i].MarkRunning(detail);
            }
            else
            {
                Steps[i].MarkPending();
            }
        }
    }

    public void MarkComplete(string result)
    {
        foreach (var step in Steps)
        {
            step.MarkComplete();
        }

        Percent = 100;
        CurrentOperation = "complete";
        Result = result;
        IsRunning = false;
    }

    public void MarkFailed(string detail)
    {
        Percent = 100;
        CurrentOperation = "failed";
        Result = detail;

        foreach (var step in Steps)
        {
            if (step.IsRunning)
            {
                step.MarkFailed(detail);
            }
        }

        IsRunning = false;
    }
}

public sealed class OneTouchProgressStepViewModel : ObservableObject
{
    private string _status = "PENDING";
    private string _detail = "waiting";

    public OneTouchProgressStepViewModel(int index, string name)
    {
        Index = index;
        Name = name;
    }

    public int Index { get; }

    public string Name { get; }

    public string Status
    {
        get => _status;
        private set
        {
            if (SetProperty(ref _status, value))
            {
                OnPropertyChanged(nameof(Line));
                OnPropertyChanged(nameof(IsRunning));
            }
        }
    }

    public string Detail
    {
        get => _detail;
        private set => SetProperty(ref _detail, value);
    }

    public string Line => $"[{Status}] {Index}. {Name}";

    public bool IsRunning => Status == "RUNNING";

    public void MarkPending()
    {
        Status = "PENDING";
        Detail = "waiting";
    }

    public void MarkRunning(string detail)
    {
        Status = "RUNNING";
        Detail = detail;
    }

    public void MarkComplete()
    {
        Status = "DONE";
        Detail = "completed";
    }

    public void MarkFailed(string detail)
    {
        Status = "FAILED";
        Detail = detail;
    }
}
