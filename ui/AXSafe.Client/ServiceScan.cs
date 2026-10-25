using System.Text.Json;

namespace AXSafe.Client;

/// <summary>
/// Scan über den AXSafe-Dienst: Der Dienst liest die Dateien mit den Rechten
/// des angemeldeten Benutzers. Der Bericht wird genauso geprüft wie bei der
/// CLI (Schema, Auftragskennung, Pfade, Zähler); er wird nie angezeigt, wenn
/// eine Prüfung scheitert.
/// </summary>
public static class ServiceScan
{
    private static readonly Dictionary<string, int> OutcomeToExit =
        ReportValidator.ExitToOutcome.ToDictionary(kv => kv.Value, kv => kv.Key);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static async Task<ScanResult> RunAsync(IReadOnlyList<string> paths, bool useClamav, CancellationToken ct, string? saveDir = null)
    {
        var abs = paths.Select(Path.GetFullPath).ToList();
        using var c = ServiceClient.Connect(5000);
        var start = await c.CallAsync(ServiceClient.ScanStart(abs, useClamav), CancellationToken.None).ConfigureAwait(false);
        if (start["ok"]?.GetValue<bool>() != true)
            return ScanResult.Failed(Guid.Empty, null, $"Dienst lehnt den Auftrag ab: {start["error"]?["message"]}");
        var jobText = (string?)start["result"]?["job_id"];
        if (!Guid.TryParse(jobText, out var jobId))
            return ScanResult.Failed(Guid.Empty, null, "Dienst lieferte keine gültige Auftragskennung.");

        string state;
        while (true)
        {
            if (ct.IsCancellationRequested)
            {
                await c.CallAsync(ServiceClient.ScanCancel(jobText!), CancellationToken.None).ConfigureAwait(false);
                return new ScanResult(jobId, false, null, null, null, "Abgebrochen. Es liegt kein Ergebnis vor.", true);
            }
            await Task.Delay(250, CancellationToken.None).ConfigureAwait(false);
            var j = await c.CallAsync(ServiceClient.Job(jobText!), CancellationToken.None).ConfigureAwait(false);
            if (j["ok"]?.GetValue<bool>() != true)
                return ScanResult.Failed(jobId, null, $"Auftrag nicht abrufbar: {j["error"]?["message"]}");
            state = (string?)j["result"]?["state"] ?? "";
            if (state is "finished" or "failed") break;
        }
        if (state == "failed")
            return ScanResult.Failed(jobId, null, "Der Dienst konnte den Auftrag nicht abschließen.");

        var rep = await c.CallAsync(ServiceClient.Report(jobText!), CancellationToken.None).ConfigureAwait(false);
        if (rep["ok"]?.GetValue<bool>() != true)
            return ScanResult.Failed(jobId, null, $"Bericht nicht abrufbar: {rep["error"]?["message"]}");
        ScanReport? report;
        try
        {
            report = rep["result"]?["report"]?.Deserialize<ScanReport>();
        }
        catch (JsonException ex)
        {
            return ScanResult.Failed(jobId, null, $"Bericht unlesbar: {ex.Message}");
        }
        if (report is null)
            return ScanResult.Failed(jobId, null, "Bericht ist leer.");
        var exit = OutcomeToExit.TryGetValue(report.Outcome, out var e) ? e : -1;
        var problems = ReportValidator.Validate(report, jobId, abs, exit).ToList();
        if (report.ExecutedBy?.Kind != "dienst")
            problems.Add("Bericht nennt nicht den Dienst als Ausführenden.");
        if (problems.Count > 0)
            return ScanResult.Failed(jobId, exit, "Bericht abgelehnt: " + string.Join(" ", problems));
        string? saved = null;
        if (saveDir is not null)
        {
            // Geprüften Bericht unverändert ablegen (nie überschreiben), damit
            // er später nachvollziehbar bleibt; der Dienstordner ist für
            // Benutzer bewusst nicht lesbar.
            try
            {
                Directory.CreateDirectory(saveDir);
                saved = Path.Combine(saveDir, $"dienst-{jobId:D}.json");
                using var fs = new FileStream(saved, FileMode.CreateNew, FileAccess.Write);
                using var w = new StreamWriter(fs, new System.Text.UTF8Encoding(false));
                w.Write(rep["result"]!["report"]!.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                saved = null;
            }
        }
        return new ScanResult(jobId, true, report, saved, exit, null, false);
    }
}
