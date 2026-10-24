using System.IO;
using AXSafe.Client;

namespace AXSafe.Desktop;

/// <summary>
/// Findet die AXSafe-CLI. Wichtig: Windows unterscheidet nicht zwischen
/// AXSafe.exe (Oberfläche) und axsafe.exe (CLI). Die CLI liegt deshalb im
/// Unterordner "cli", und die eigene Programmdatei wird ausgeschlossen.
/// </summary>
public static class CliLocator
{
    public static string ReportsDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AXSafe", "reports");

    public static AxsafeCliClient? Create()
    {
        var baseDir = AppContext.BaseDirectory;
        var self = Environment.ProcessPath ?? "";
        var candidates = new List<string> { Path.Combine(baseDir, "cli", "axsafe.exe") };
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try { candidates.Add(Path.Combine(dir.Trim(), "axsafe.exe")); } catch (ArgumentException) { }
        }
        var exe = candidates.FirstOrDefault(c =>
            File.Exists(c) &&
            !string.Equals(Path.GetFullPath(c), Path.GetFullPath(self), StringComparison.OrdinalIgnoreCase));
        if (exe is null) return null;
        var rules = Path.Combine(Path.GetDirectoryName(exe)!, "rules");
        return new AxsafeCliClient(exe, ReportsDir, Directory.Exists(rules) ? rules : null);
    }
}
