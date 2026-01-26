using System;
using System.Diagnostics;
using System.IO;

namespace TGWST.Core.Utils
{
    public static class Sandbox
    {
        /// <summary>
        /// Generates a temporary .wsb configuration file to mount the target folder 
        /// into Windows Sandbox safely (Read-Only, No Network) and launches it.
        /// </summary>
        /// <param name="folderPath">The host directory containing suspicious files.</param>
        public static void Detonate(string folderPath)
        {
            // Windows Sandbox Configuration (XML)
            // 1. vGPU: Enabled for performance (or Disable for maximum isolation)
            // 2. Networking: Disable (Prevent malware from calling home)
            // 3. MappedFolder: Mounts the suspicious folder as ReadOnly
            // 4. LogonCommand: Automatically opens the folder in Explorer upon boot
            string wsbContent = $@"
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{folderPath}</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\SuspiciousFiles</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>explorer.exe C:\Users\WDAGUtilityAccount\Desktop\SuspiciousFiles</Command>
  </LogonCommand>
</Configuration>";

            // Save to a temp file with .wsb extension
            string tempFile = Path.Combine(Path.GetTempPath(), $"TGWST_Detonate_{Guid.NewGuid()}.wsb");
            File.WriteAllText(tempFile, wsbContent);

            // Launching a .wsb file triggers the Windows Sandbox application
            try 
            {
                Process.Start(new ProcessStartInfo(tempFile) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                // In a real app, you'd want to catch if Windows Sandbox isn't installed
                // Feature name: "Containers-DisposableClientVM"
                throw new InvalidOperationException("Failed to launch Windows Sandbox. Ensure the feature is enabled in Windows.", ex);
            }
        }
    }
}