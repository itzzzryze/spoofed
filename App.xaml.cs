using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace SystemHardwareAudit;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        base.OnStartup(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        ReportFatalError(e.Exception);
        e.Handled = true;
        Shutdown(-1);
    }

    private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception exception)
            ReportFatalError(exception);
    }

    private static void ReportFatalError(Exception exception)
    {
        string? logPath = null;

        try
        {
            string logFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Spoofed");
            Directory.CreateDirectory(logFolder);
            logPath = Path.Combine(logFolder, "startup-error.log");
            File.WriteAllText(
                logPath,
                $"Time: {DateTimeOffset.Now:O}{Environment.NewLine}" +
                $"Version: {typeof(App).Assembly.GetName().Version}{Environment.NewLine}" +
                $"Windows: {Environment.OSVersion}{Environment.NewLine}{Environment.NewLine}" +
                exception);
        }
        catch
        {
            // The error dialog still works if the log cannot be written.
        }

        string message = "spoofed? could not start.\n\n" + exception.Message;
        if (logPath != null)
            message += "\n\nError log:\n" + logPath;

        MessageBox.Show(message, "spoofed?", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}

