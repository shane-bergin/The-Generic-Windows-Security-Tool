using System.Windows.Input;
using TGWST.Core.Services;
using TGWST.Core.Utils;
using System.IO;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace TGWST.App.ViewModels
{
    // Ensure this inherits from your ViewModelBase (or ObservableObject if using CommunityToolkit)
    public class MainViewModel : ObservableObject 
    {
        private readonly NativeScanner _scanner;
        private readonly LocalIntelligence _ai;

        // Constructor Injection: The App asks for these, and DI provides them automatically
        public MainViewModel(NativeScanner scanner, LocalIntelligence ai)
        {
            _scanner = scanner;
            _ai = ai;

            ScanCommand = new RelayCommand(ExecuteScan);
            DetonateCommand = new RelayCommand(ExecuteDetonate);
        }

        public ICommand ScanCommand { get; }
        public ICommand DetonateCommand { get; }

        private void ExecuteScan()
        {
            // Test logic: Scan a dummy buffer
            byte[] eicar = System.Text.Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
            
            bool isClean = _scanner.ScanContent(eicar, "eicar_test_file");
            
            // In a real app, bind this result to a UI property
            System.Diagnostics.Debug.WriteLine($"Scan Result: {(isClean ? "Clean" : "Malware Detected")}");
        }

        private void ExecuteDetonate()
        {
            // Uses the Sandbox utility we created
            // For now, let's just test it on the temp folder to be safe
            Sandbox.Detonate(Path.GetTempPath()); 
        }
    }
}
