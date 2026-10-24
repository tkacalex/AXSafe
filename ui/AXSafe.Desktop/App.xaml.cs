using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace AXSafe.Desktop;

/// <summary>
/// AXSafe Desktop (Vorversion). Läuft mit normalen Benutzerrechten (AXS-013)
/// und benötigt kein Konto (AXS-090).
/// </summary>
public partial class App : Application
{
    public static string LogDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AXSafe", "logs");

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            WriteCrashLog(args.ExceptionObject as Exception);
        base.OnStartup(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var path = WriteCrashLog(e.Exception);
        MessageBox.Show(
            "AXSafe ist auf einen unerwarteten Fehler gestoßen und wird beendet.\n\n" +
            $"Ein Fehlerprotokoll (ohne Dateiinhalte) liegt hier:\n{path}\n\n" +
            "Bitte melde den Fehler auf github.com/tkacalex/AXSafe/issues.",
            "AXSafe – Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
        Shutdown(1);
    }

    /// <summary>Schreibt Ausnahme und Version. Keine Dateiinhalte, keine Geheimnisse.</summary>
    private static string? WriteCrashLog(Exception? ex)
    {
        try
        {
            Directory.CreateDirectory(LogDir);
            var path = Path.Combine(LogDir, $"crash-{DateTime.UtcNow:yyyyMMdd-HHmmss}.log");
            File.WriteAllText(path,
                $"AXSafe Desktop {typeof(App).Assembly.GetName().Version}\n" +
                $"Zeit (UTC): {DateTime.UtcNow:O}\nOS: {Environment.OSVersion}\n\n{ex}");
            return path;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }
}
