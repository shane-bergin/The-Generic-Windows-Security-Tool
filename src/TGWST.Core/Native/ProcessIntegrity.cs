using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace TGWST.Core.Native;

/// <summary>
/// Native helpers for process token integrity level (used for LPE / SYSTEM shell detection).
/// </summary>
public static class ProcessIntegrity
{
    public enum IntegrityLevel
    {
        Unknown = 0,
        Untrusted = 0x0000,
        Low = 0x1000,
        Medium = 0x2000,
        MediumPlus = 0x2100,
        High = 0x3000,
        System = 0x4000,
        ProtectedProcess = 0x5000
    }

    public static IntegrityLevel GetIntegrityLevel(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return GetIntegrityLevel(process);
        }
        catch
        {
            return IntegrityLevel.Unknown;
        }
    }

    public static IntegrityLevel GetIntegrityLevel(Process process)
    {
        if (process == null) return IntegrityLevel.Unknown;

        SafeProcessHandle? hProcess = null;
        SafeTokenHandle? hToken = null;
        try
        {
            hProcess = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, process.Id);
            if (hProcess == null || hProcess.IsInvalid) return IntegrityLevel.Unknown;

            if (!OpenProcessToken(hProcess, TOKEN_QUERY, out hToken) || hToken.IsInvalid)
                return IntegrityLevel.Unknown;

            if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, out var tokenInformation))
                return IntegrityLevel.Unknown;

            try
            {
                var integritySid = Marshal.ReadIntPtr(tokenInformation);
                if (integritySid == IntPtr.Zero || !IsValidSid(integritySid))
                    return IntegrityLevel.Unknown;

                var subAuthorityCountPointer = GetSidSubAuthorityCount(integritySid);
                if (subAuthorityCountPointer == IntPtr.Zero)
                    return IntegrityLevel.Unknown;

                var subAuthorityCount = Marshal.ReadByte(subAuthorityCountPointer);
                if (subAuthorityCount == 0)
                    return IntegrityLevel.Unknown;

                var integrityRidPointer = GetSidSubAuthority(integritySid, subAuthorityCount - 1);
                if (integrityRidPointer == IntPtr.Zero)
                    return IntegrityLevel.Unknown;

                var rid = Marshal.ReadInt32(integrityRidPointer);
                return (IntegrityLevel)rid;
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInformation);
            }
        }
        catch
        {
            return IntegrityLevel.Unknown;
        }
        finally
        {
            hToken?.Dispose();
            hProcess?.Dispose();
        }
    }

    public static bool IsSystemOrHigh(IntegrityLevel level) =>
        level == IntegrityLevel.System || level == IntegrityLevel.High || level == IntegrityLevel.ProtectedProcess;

    public static string ToDisplay(IntegrityLevel level) => level switch
    {
        IntegrityLevel.System => "SYSTEM",
        IntegrityLevel.High => "HIGH",
        IntegrityLevel.MediumPlus => "MEDIUM_PLUS",
        IntegrityLevel.Medium => "MEDIUM",
        IntegrityLevel.Low => "LOW",
        _ => level.ToString().ToUpperInvariant()
    };

    #region P/Invoke

    private const uint TOKEN_QUERY = 0x0008;

    [Flags]
    private enum ProcessAccessFlags : uint
    {
        QueryLimitedInformation = 0x1000
    }

    private enum TOKEN_INFORMATION_CLASS
    {
        TokenIntegrityLevel = 25
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(SafeProcessHandle processHandle, uint desiredAccess, out SafeTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeTokenHandle tokenHandle,
        TOKEN_INFORMATION_CLASS tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsValidSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern IntPtr GetSidSubAuthority(IntPtr sid, int subAuthority);

    private static bool GetTokenInformation(SafeTokenHandle tokenHandle, TOKEN_INFORMATION_CLASS infoClass, out IntPtr tokenInformation)
    {
        tokenInformation = IntPtr.Zero;
        uint length = 0;
        GetTokenInformation(tokenHandle, infoClass, IntPtr.Zero, 0, out length);
        if (length == 0) return false;

        tokenInformation = Marshal.AllocHGlobal((int)length);
        bool ok = GetTokenInformation(tokenHandle, infoClass, tokenInformation, length, out _);
        if (!ok)
        {
            Marshal.FreeHGlobal(tokenInformation);
            tokenInformation = IntPtr.Zero;
        }
        return ok;
    }

    private sealed class SafeProcessHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeProcessHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseHandle(handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);
    }

    private sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeTokenHandle() : base(true) { }
        protected override bool ReleaseHandle() => CloseHandle(handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr h);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    #endregion
}
