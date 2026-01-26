using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using TGWST.Core.Services;
using TGWST.App.ViewModels;

namespace TGWST.App
{
    public partial class App : System.Windows.Application
    {
        public IServiceProvider ServiceProvider { get; private set; }

        protected override void OnStartup(StartupEventArgs e)
        {
            var serviceCollection = new ServiceCollection();
            ConfigureServices(serviceCollection);

            ServiceProvider = serviceCollection.BuildServiceProvider();

            // Resolve the Main Window and show it
            var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
            mainWindow.Show();

            base.OnStartup(e);
        }

        private void ConfigureServices(IServiceCollection services)
        {
            // 1. Register Core Native Services (Singletons = created once, reused)
            services.AddSingleton<NativeScanner>();
            services.AddSingleton<LocalIntelligence>();

            // 2. Register ViewModels
            services.AddTransient<MainViewModel>();

            // 3. Register Views
            services.AddSingleton<MainWindow>();
        }
    }
}