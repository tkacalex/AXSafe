using System.Diagnostics;
using System.Text.Json;

namespace AXSafe.Client;

/// <summary>Ergebnis eines Scanauftrags aus Sicht der Oberfläche.</summary>
public sealed record ScanResult(
    Guid JobId,
    bool Success,
    ScanReport? Report,
    string? ReportPath,
    int? ExitCode,
    string? Error,
    bool Cancelled)
{
    public static ScanResult Failed(Guid jobId, int? exit, string error, string? path = null) =>
        new(jobId, false, null, path, exit, error, false);
}

/// <summary>
/// Startet die echte AXSafe-CLI für genau einen Auftrag und verknüpft das
/// Ergebnis eindeutig mit diesem Auftrag (Befund 5):
/// zufällige Auftragskennung, exklusives Berichtsziel mit dieser Kennung im
/// Namen, Validierung von Schema, Kennung, Pfaden und Exitcode. Es wird nie ein
/// anderer (älterer) Bericht gelesen. Es wird keine Shell verwendet.
/// </summary>
public sealed class AxsafeCliClient
{
    public string ExePath { get; }
    public string ReportsDir { get; }
    public string? RulesDir { get; }

    public AxsafeCliClient(string exePath, string reportsDir, string? rulesDir)
    {
        ExePath = exePath;
        ReportsDir = reportsDir;
        RulesDir = rulesDir;
    }

    public async Task<List<EngineInfo>?> GetEnginesAsync(bool useClamav, CancellationToken ct)
    {
        var psi = NewStartInfo();
        psi.ArgumentList.Add("engines");
        psi.ArgumentList.Add("--json");
        AddEngineArgs(psi, useClamav);
        var run = await RunAsync(psi, ct).ConfigureAwait(false);
        if (run.StartError is not null || run.ExitCode is not (0 or 2)) return null;
        try
        {
            return JsonSerializer.Deserialize<List<EngineInfo>>(run.Stdout);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public async Task<ScanResult> ScanAsync(IReadOnlyList<string> paths, bool useClamav, CancellationToken ct)
    {
        var jobId = Guid.NewGuid();
        string reportPath;
        try
        {
            Directory.CreateDirectory(ReportsDir);
            reportPath = Path.Combine(ReportsDir, $"scan-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}-{jobId:N}.json");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return ScanResult.Failed(jobId, null, $"Berichtsordner nicht nutzbar: {ex.Message}");
        }

        var psi = NewStartInfo();
        psi.ArgumentList.Add("scan");
        psi.ArgumentList.Add("--job-id");
        psi.ArgumentList.Add(jobId.ToString("D"));
        psi.ArgumentList.Add("--json");
        psi.ArgumentList.Add(reportPath);
        AddEngineArgs(psi, useClamav);
        psi.ArgumentList.Add("--");
        foreach (var p in paths) psi.ArgumentList.Add(p);

        CliRun run;
        try
        {
            run = await RunAsync(psi, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return new ScanResult(jobId, false, null, null, null, "Abgebrochen. Es liegt kein Ergebnis vor.", true);
        }
        if (run.StartError is not null)
            return ScanResult.Failed(jobId, null, run.StartError);
        if (run.ExitCode is null || !ReportValidator.ExitToOutcome.ContainsKey(run.ExitCode.Value))
        {
            var msg = string.IsNullOrWhiteSpace(run.Stderr) ? "AXSafe meldete einen Fehler." : run.Stderr.Trim();
            return ScanResult.Failed(jobId, run.ExitCode, msg);
        }

        ScanReport? report;
        try
        {
            // Nur genau das Ziel dieses Auftrags lesen.
            await using var fs = new FileStream(reportPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            report = await JsonSerializer.DeserializeAsync<ScanReport>(fs, cancellationToken: ct).ConfigureAwait(false);
        }
        catch (FileNotFoundException)
        {
            return ScanResult.Failed(jobId, run.ExitCode, "Es wurde kein Bericht für diesen Auftrag erzeugt.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return ScanResult.Failed(jobId, run.ExitCode, $"Bericht nicht lesbar: {ex.Message}", reportPath);
        }
        if (report is null)
            return ScanResult.Failed(jobId, run.ExitCode, "Bericht ist leer.", reportPath);

        var problems = ReportValidator.Validate(report, jobId, paths, run.ExitCode.Value);
        if (problems.Count > 0)
            return ScanResult.Failed(jobId, run.ExitCode, "Bericht abgelehnt: " + string.Join(" ", problems), reportPath);
        return new ScanResult(jobId, true, report, reportPath, run.ExitCode, null, false);
    }

    private ProcessStartInfo NewStartInfo() => new()
    {
        FileName = ExePath,
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        StandardOutputEncoding = System.Text.Encoding.UTF8,
        StandardErrorEncoding = System.Text.Encoding.UTF8,
    };

    private void AddEngineArgs(ProcessStartInfo psi, bool useClamav)
    {
        if (RulesDir is not null)
        {
            psi.ArgumentList.Add("--rules");
            psi.ArgumentList.Add(RulesDir);
        }
        if (!useClamav) psi.ArgumentList.Add("--no-clamav");
    }

    private sealed record CliRun(int? ExitCode, string Stdout, string Stderr, string? StartError);

    private static async Task<CliRun> RunAsync(ProcessStartInfo psi, CancellationToken ct)
    {
        using var proc = new Process { StartInfo = psi };
        try
        {
            proc.Start();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new CliRun(null, "", "", $"axsafe konnte nicht gestartet werden: {ex.Message}");
        }
        var outTask = proc.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var errTask = proc.StandardError.ReadToEndAsync(CancellationToken.None);
        try
        {
            await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            throw;
        }
        return new CliRun(proc.ExitCode, await outTask.ConfigureAwait(false), await errTask.ConfigureAwait(false), null);
    }
}
