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
    /// <summary>Fortsetzungsdatei eines abgebrochenen Auftrags (falls vorhanden).</summary>
    public string? ResumePath { get; init; }

    public static ScanResult Failed(Guid jobId, int? exit, string error, string? path = null) =>
        new(jobId, false, null, path, exit, error, false);
}

/// <summary>Fortschritt: Objekte bisher, vorab gezählte Gesamtzahl (falls bekannt).</summary>
public sealed record ScanProgressInfo(long Objects, long? Total, long Bytes, string? Current)
{
    public double? Percent => Total is > 0 ? Math.Min(99.0, Objects * 100.0 / Total.Value) : null;
}

/// <summary>Scanart (AXS-026): custom, quick, full, removable; Auslöser manual, context_menu, schedule.</summary>
public sealed record ScanOptions(string Kind = "custom", string Trigger = "manual", string? ResumeFrom = null, IProgress<ScanProgressInfo>? Progress = null)
{
    public static string CliKind(string kind) => kind switch
    {
        "quick" => "schnell",
        "full" => "voll",
        "removable" => "wechsel",
        _ => "benutzer",
    };
    public static string CliTrigger(string t) => t switch
    {
        "context_menu" => "kontextmenue",
        "schedule" => "zeitplan",
        _ => "manuell",
    };
}

/// <summary>Ziele einer Scanart, wie die CLI sie bestimmt.</summary>
public sealed record ScanTargets(string Kind, List<string> Roots, List<string> Missing, string Note);

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

    /// <summary>Betriebszustand (AXS-019). <c>null</c> = keine gültige Antwort.</summary>
    public async Task<HealthReport?> GetHealthAsync(bool useClamav, CancellationToken ct)
    {
        var psi = NewStartInfo();
        psi.ArgumentList.Add("zustand");
        psi.ArgumentList.Add("--json");
        AddEngineArgs(psi, useClamav);
        var run = await RunAsync(psi, ct).ConfigureAwait(false);
        if (run.StartError is not null || run.ExitCode is not (0 or 2 or 3)) return null;
        return HealthView.Parse(run.Stdout);
    }

    /// <summary>Ziele einer Scanart (z. B. Downloads und Temp für die Schnellprüfung).</summary>
    public async Task<ScanTargets?> GetTargetsAsync(string kind, CancellationToken ct)
    {
        var psi = NewStartInfo();
        psi.ArgumentList.Add("ziele");
        psi.ArgumentList.Add("--art");
        psi.ArgumentList.Add(ScanOptions.CliKind(kind));
        psi.ArgumentList.Add("--json");
        var run = await RunAsync(psi, ct).ConfigureAwait(false);
        if (run.StartError is not null || run.ExitCode != 0) return null;
        try
        {
            var n = System.Text.Json.Nodes.JsonNode.Parse(run.Stdout);
            if (n is null) return null;
            return new ScanTargets(
                (string?)n["kind"] ?? "",
                n["roots"]?.AsArray().Select(x => (string)x!).ToList() ?? new(),
                n["missing"]?.AsArray().Select(x => (string)x!).ToList() ?? new(),
                (string?)n["note"] ?? "");
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>Ziele (Wurzeln) aus der Kopfzeile einer Fortsetzungsdatei.</summary>
    public static (string Kind, List<string> Roots)? ReadResumeHeader(string path)
    {
        try
        {
            using var r = new StreamReader(path);
            var line = r.ReadLine();
            if (line is null || line.Length > 1_000_000) return null;
            var n = System.Text.Json.Nodes.JsonNode.Parse(line);
            if ((string?)n?["schema"] != "axsafe.fortsetzung/1") return null;
            return ((string?)n!["kind"] ?? "custom", n["roots"]?.AsArray().Select(x => (string)x!).ToList() ?? new());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    public Task<ScanResult> ScanAsync(IReadOnlyList<string> paths, bool useClamav, CancellationToken ct) =>
        ScanAsync(paths, useClamav, new ScanOptions(), ct);

    public async Task<ScanResult> ScanAsync(IReadOnlyList<string> paths, bool useClamav, ScanOptions opt, CancellationToken ct)
    {
        var jobId = Guid.NewGuid();
        // Erwartete Wurzeln: angegebene Pfade, Ziele der Scanart oder die
        // Ziele des fortgesetzten Auftrags.
        IReadOnlyList<string> expectedRoots = paths;
        var expectedKind = opt.Kind;
        if (opt.ResumeFrom is not null)
        {
            var h = ReadResumeHeader(opt.ResumeFrom);
            if (h is null) return ScanResult.Failed(jobId, null, "Fortsetzungsdatei nicht lesbar oder ungültig.");
            expectedRoots = h.Value.Roots;
            expectedKind = h.Value.Kind;
        }
        else if (opt.Kind != "custom")
        {
            var t = await GetTargetsAsync(opt.Kind, ct).ConfigureAwait(false);
            if (t is null) return ScanResult.Failed(jobId, null, "Ziele der Scanart nicht ermittelbar.");
            if (t.Roots.Count == 0) return ScanResult.Failed(jobId, null, "Für diese Scanart gibt es auf diesem Rechner keine Ziele.");
            expectedRoots = t.Roots;
        }
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
        var resumePath = Path.Combine(ReportsDir, $"fortsetzung-{jobId:N}.jsonl");
        psi.ArgumentList.Add("--fortsetzungsdatei");
        psi.ArgumentList.Add(resumePath);
        psi.ArgumentList.Add("--fortschritt-json");
        psi.ArgumentList.Add("--ausloeser");
        psi.ArgumentList.Add(ScanOptions.CliTrigger(opt.Trigger));
        AddEngineArgs(psi, useClamav);
        if (opt.ResumeFrom is not null)
        {
            psi.ArgumentList.Add("--fortsetzen");
            psi.ArgumentList.Add(opt.ResumeFrom);
        }
        else if (opt.Kind != "custom")
        {
            psi.ArgumentList.Add("--art");
            psi.ArgumentList.Add(ScanOptions.CliKind(opt.Kind));
        }
        else
        {
            psi.ArgumentList.Add("--");
            foreach (var p in paths) psi.ArgumentList.Add(p);
        }

        CliRun run;
        try
        {
            run = await RunAsync(psi, ct, opt.Progress).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Bereits geprüfte Objekte stehen in der Fortsetzungsdatei.
            return new ScanResult(jobId, false, null, null, null, "Abgebrochen. Es liegt kein Ergebnis vor.", true)
            {
                ResumePath = File.Exists(resumePath) ? resumePath : null,
            };
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

        var problems = ReportValidator.Validate(report, jobId, expectedRoots, run.ExitCode.Value, expectedKind);
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

    private static async Task<CliRun> RunAsync(ProcessStartInfo psi, CancellationToken ct, IProgress<ScanProgressInfo>? progress = null)
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
        var errTask = ReadStderrAsync(proc.StandardError, progress);
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

    /// <summary>Liest stderr vollständig; Fortschrittszeilen (JSON) werden gemeldet.</summary>
    private static async Task<string> ReadStderrAsync(StreamReader r, IProgress<ScanProgressInfo>? progress)
    {
        var sb = new System.Text.StringBuilder();
        string? line;
        while ((line = await r.ReadLineAsync().ConfigureAwait(false)) is not null)
        {
            if (TryParseProgress(line) is { } p)
            {
                progress?.Report(p);
                continue;
            }
            sb.AppendLine(line);
        }
        return sb.ToString();
    }

    public static ScanProgressInfo? TryParseProgress(string line)
    {
        if (!line.StartsWith("{\"fortschritt\"", StringComparison.Ordinal)) return null;
        try
        {
            var n = System.Text.Json.Nodes.JsonNode.Parse(line)?["fortschritt"];
            if (n is null) return null;
            return new ScanProgressInfo((long?)n["objekte"] ?? 0, (long?)n["gesamt"], (long?)n["bytes"] ?? 0, (string?)n["aktuell"]);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
