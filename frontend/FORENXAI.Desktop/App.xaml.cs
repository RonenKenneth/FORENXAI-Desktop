using System;
using System.Windows;

using FORENXAI.Desktop.Services;

namespace FORENXAI.Desktop;

public partial class App : Application
{
    private BackendProcessService? backendProcessService;


    // =========================================================
    // APPLICATION STARTUP
    // =========================================================

    protected override async void OnStartup(
        StartupEventArgs e)
    {
        backendProcessService =
            new BackendProcessService();

        try
        {
            await backendProcessService
                .EnsureBackendRunningAsync();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                "FORENXAI could not start its backend service.\n\n" +
                ex.Message,
                "FORENXAI Startup Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error
            );

            Shutdown();
            return;
        }

        base.OnStartup(e);
    }


    // =========================================================
    // APPLICATION SHUTDOWN
    // =========================================================

    protected override void OnExit(
        ExitEventArgs e)
    {
        try
        {
            backendProcessService?
                .StopBackendIfOwned();
        }
        catch
        {
            // Application shutdown must continue even if
            // the backend process has already exited.
        }

        backendProcessService?
            .Dispose();

        base.OnExit(e);
    }
}
