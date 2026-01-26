using System;
using System.Runtime.InteropServices;

namespace TGWST.Core.Services
{
    public class NativeScanner : IDisposable
    {
        private IntPtr _amsiContext;
        private IntPtr _amsiSession;

        public NativeScanner()
        {
            AmsiInitialize("TGWST", out _amsiContext);
            AmsiOpenSession(_amsiContext, out _amsiSession);
        }

        public bool ScanContent(byte[] content, string contentName)
        {
            if (content == null || content.Length == 0)
            {
                return true;
            }

            var result = AmsiScanBuffer(_amsiContext, content, (uint)content.Length, contentName, _amsiSession, out var scanResult);

            if (result != 0)
            {
                // An error occurred during the scan
                throw new Exception($"AMSI scan failed with error code: {result}");
            }

            return AmsiResultIsMalware(scanResult) == false;
        }

        public void Dispose()
        {
            AmsiCloseSession(_amsiContext, _amsiSession);
            AmsiUninitialize(_amsiContext);
        }

        [DllImport("amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiInitialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]
        public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
        public static extern int AmsiScanBuffer(IntPtr amsiContext, byte[] buffer, uint length, [MarshalAs(UnmanagedType.LPWStr)] string contentName, IntPtr session, out int result);

        [DllImport("amsi.dll", EntryPoint = "AmsiResultIsMalware", CallingConvention = CallingConvention.StdCall)]
        public static extern bool AmsiResultIsMalware(int result);
    }
}
