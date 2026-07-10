using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace TGWST.App.Services;

public sealed class SuspendedProcessDetector
{
    private const int ThreadQueryInformation = 0x0040;
    private const int ThreadQueryLimitedInformation = 0x0800;
    private const int ThreadSuspendCount = 35;

    public async Task<SuspendedProcessInspection?> InspectRecentStartAsync(
        int processId,
        string processName,
        CancellationToken ct)
    {
        SuspendedProcessInspection? lastInspection = null;
        foreach (var delay in new[] { 75, 300, 900 })
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(delay, ct).ConfigureAwait(false);
            lastInspection = Inspect(processId, processName);
            if (lastInspection?.SuspendedThreadCount > 0)
            {
                return lastInspection;
            }
        }

        return lastInspection;
    }

    private static SuspendedProcessInspection? Inspect(int processId, string processName)
    {
        if (processId <= 0)
        {
            return null;
        }

        try
        {
            using var process = Process.GetProcessById(processId);
            var threadCount = 0;
            var suspendedThreadCount = 0;

            foreach (ProcessThread thread in process.Threads)
            {
                threadCount++;
                using (thread)
                {
                    if (TryReadThreadSuspendCount(thread.Id, out var suspendCount) && suspendCount > 0)
                    {
                        suspendedThreadCount++;
                    }
                }
            }

            return threadCount == 0
                ? null
                : new SuspendedProcessInspection(processId, processName, threadCount, suspendedThreadCount);
        }
        catch
        {
            return null;
        }
    }

    private static bool TryReadThreadSuspendCount(int threadId, out int suspendCount)
    {
        suspendCount = 0;
        using var handle = OpenThread(
            ThreadQueryInformation | ThreadQueryLimitedInformation,
            inheritHandle: false,
            threadId);

        if (handle.IsInvalid)
        {
            return false;
        }

        var status = NtQueryInformationThread(
            handle,
            ThreadSuspendCount,
            out suspendCount,
            sizeof(int),
            out _);

        return status == 0;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeThreadHandle OpenThread(
        int desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        int threadId);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationThread(
        SafeThreadHandle threadHandle,
        int threadInformationClass,
        out int threadInformation,
        int threadInformationLength,
        out int returnLength);

    private sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeThreadHandle()
            : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return CloseHandle(handle);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}

public sealed record SuspendedProcessInspection(
    int ProcessId,
    string ProcessName,
    int ThreadCount,
    int SuspendedThreadCount);
