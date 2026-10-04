using System.Windows;
using DLD.DroidGuard.App.ViewModels;
using DLD.DroidGuard.Core.Abstractions;
using DLD.DroidGuard.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace DLD.DroidGuard.App;

public partial class App : Application
{
    private ServiceProvider? _serviceProvider;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var services = new ServiceCollection();
        ConfigureServices(services);
        _serviceProvider = services.BuildServiceProvider();

        var mainWindow = _serviceProvider.GetRequiredService<MainWindow>();
        mainWindow.Show();

        // Fire-and-forget initialisation (runs async after window is shown)
        var vm = _serviceProvider.GetRequiredService<MainViewModel>();
        await vm.InitialiseAsync();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _serviceProvider?.Dispose();
        base.OnExit(e);
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Logging
        services.AddLogging(logging =>
        {
            logging.SetMinimumLevel(LogLevel.Debug);
            logging.AddConsole();
        });

        // ADB + device services
        services.AddDroidGuardAdb(configuredAdbPath: null);

        // ViewModels
        services.AddTransient<MainViewModel>();

        // Views
        services.AddTransient<MainWindow>(sp =>
        {
            var vm = sp.GetRequiredService<MainViewModel>();
            var window = new MainWindow { DataContext = vm };
            return window;
        });
    }
}
