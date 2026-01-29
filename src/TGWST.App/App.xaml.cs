using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using TGWST.Core.Services;
using TGWST.App.Shell;
using TGWST.App.Shell.Commands;
using TGWST.App.ViewModels;
using TGWST.App.Views;
using TGWST.Core.Audit;
using TGWST.Core.Policies;

namespace TGWST.App
{
    public partial class App : System.Windows.Application
    {
        public IServiceProvider ServiceProvider { get; private set; } = null!;

        protected override void OnStartup(StartupEventArgs e)
        {
            var serviceCollection = new ServiceCollection();
            ConfigureServices(serviceCollection);

            ServiceProvider = serviceCollection.BuildServiceProvider();

            // Resolve the Shell View and show it
            var shellView = ServiceProvider.GetRequiredService<ShellView>();
            MainWindow = shellView;
            shellView.Show();

            base.OnStartup(e);
        }

        private void ConfigureServices(IServiceCollection services)
        {
            // 1. Register Core Native Services (Singletons = created once, reused)
            services.AddSingleton<NativeScanner>();
            services.AddSingleton<LocalIntelligence>();

            // 2. Register ViewModels
            services.AddTransient<MainViewModel>();
            services.AddTransient<ShellViewModel>();

            // 3. Register Shell Infrastructure
            services.AddSingleton<TaskOutputService>();
            services.AddSingleton<InsightService>();
            services.AddSingleton<AuditLogService>();
            services.AddSingleton<PolicySnapshotStore>();
            services.AddSingleton<ICommandHandler, HelpCommand>();
            services.AddSingleton<ICommandHandler, ClearCommand>();
            services.AddSingleton<ICommandHandler, QuitCommand>();
            services.AddSingleton<ICommandHandler, WdacCommand>();
            services.AddSingleton<ICommandHandler, AsrCommand>();
            services.AddSingleton<ICommandHandler, DefenderScanCommand>();
            services.AddSingleton<ICommandHandler, NetworkCommand>();
            services.AddSingleton<ICommandHandler, ComplianceCommand>();
            services.AddSingleton<ICommandHandler, UninstallCommand>();
            services.AddSingleton<CommandRegistry>();

            // 4. Register Views
            services.AddSingleton<MainWindow>();
            services.AddSingleton<ShellView>();
        }
    }
}
