using System.Diagnostics;
using System.IO;
using System.Text.Json;
using AXSafe.Desktop.Models;

namespace AXSafe.Desktop.Services;

/// <summary>
/// Anbindung an die echte AXSafe-Kommandozeile (axsafe.exe).
/// Bis der privilegierte Dienst mit Named-Pipe-IPC existiert (Phase P02),
/// startet die Oberfläche die CLI mit denselben Benutzerrechten.
/// Es wird keine Shell verwendet; Argumente werden einzeln übergeben.
/// </summary>
public sealed class AxsafeCli
{
    public string? ExePath { get; }
    public string ReportsDir { get; }

    public AxsafeCli()
    {
        ExePath = Locate();
        ReportsDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AXSafe", "reports");
    }

    public bool Available => ExePath is not null;

    private static string? Locate()
    {
        var baseDir = AppContext.BaseDirectory;
        var candidates = new List<string>
        {
            Path.Combine(baseDir, "axsafe.exe"),
            Path.Combine(baseDir, "cli", "axsafe.exe"),
        };
        var pathVar = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathVar.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try { candidates.Add(Path.Combine(dir.Trim(), "axsafe.exe")); } catch (ArgumentException) { }
        }
        return candidates.FirstOrDefault(File.Exists);
    }

    private string? RulesDir()
    {
        if (ExePath is null) return null;
        var dir = Path.Combine(Path.GetDirectoryName(ExePath)!, "rules");
        return Directory.Exists(dir) ? dir : null;
    }

    public async Task<List<EngineInfo>> GetEnginesAsync(bool useClamav, CancellationToken ct)
    {
        if (ExePath is null) return new();
        var psi = NewStartInfo();
        psi.ArgumentList.Add("engines");
        psi.ArgumentList.Add("--json");
        AddEngineArgs(psi, useClamav);
        var (code, stdout, _) = await RunAsync(psi, ct);
        if (code is not (0 or 2)) return new();
        try
        {
            return JsonSerializer.Deserialize<List<EngineInfo>>(stdout) ?? new();
        }
        catch (JsonException)
        {
            return new();
        }
    }

    public sealed record ScanOutcome(ScanReport? Report, int ExitCode, string Error, string? ReportPath);

    public async Task<ScanOutcome> ScanAsync(IReadOnlyList<string> paths, bool useClamav, CancellationToken ct)
    {
        if (ExePath is null)
            return new(null, 3, "axsafe.exe wurde nicht gefunden.", null);
        Directory.CreateDirectory(ReportsDir);
        var reportPath = Path.Combine(ReportsDir, $"scan-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json");
        var psi = NewStartInfo();
        psi.ArgumentList.Add("scan");
        AddEngineArgs(psi, useClamav);
        psi.ArgumentList.Add("--json");
        psi.ArgumentList.Add(reportPath);
        foreach (var p in paths) psi.ArgumentList.Add(p);

        var (code, _, stderr) = await RunAsync(psi, ct);
        if (!File.Exists(reportPath))
            return new(null, code, string.IsNullOrWhiteSpace(stderr) ? "Kein Bericht erzeugt." : stderr.Trim(), null);
        try
        {
            await using var fs = File.OpenRead(reportPath);
            var report = await JsonSerializer.DeserializeAsync<ScanReport>(fs, cancellationToken: ct);
            return new(report, code, stderr.Trim(), reportPath);
        }
        catch (JsonException ex)
        {
            return new(null, code, $"Bericht nicht lesbar: {ex.Message}", reportPath);
        }
    }

    private ProcessStartInfo NewStartInfo() => new()
    {
        FileName = ExePath!,
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        StandardOutputEncoding = System.Text.Encoding.UTF8,
        StandardErrorEncoding = System.Text.Encoding.UTF8,
    };

    private void AddEngineArgs(ProcessStartInfo psi, bool useClamav)
    {
        var rules = RulesDir();
        if (rules is not null)
        {
            psi.ArgumentList.Add("--rules");
            psi.ArgumentList.Add(rules);
        }
        if (!useClamav) psi.ArgumentList.Add("--no-clamav");
    }

    private static async Task<(int Code, string Stdout, string Stderr)> RunAsync(ProcessStartInfo psi, CancellationToken ct)
    {
        using var proc = new Process { StartInfo = psi };
        try
        {
            proc.Start();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return (3, "", $"Start fehlgeschlagen: {ex.Message}");
        }
        var outTask = proc.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var errTask = proc.StandardError.ReadToEndAsync(CancellationToken.None);
        try
        {
            await proc.WaitForExitAsync(ct);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw;
        }
        return (proc.ExitCode, await outTask, await errTask);
    }
}
