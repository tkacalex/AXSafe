namespace AXSafe.Client;

/// <summary>
/// Prüft, dass ein Bericht wirklich zum gestarteten Auftrag gehört (Befund 5)
/// und in sich stimmig ist. Ein Bericht, der eine Prüfung nicht besteht, wird
/// nie als Ergebnis angezeigt.
/// </summary>
public static class ReportValidator
{
    /// <summary>Zulässige CLI-Exitcodes mit Bericht und das passende Ergebnis.</summary>
    public static readonly IReadOnlyDictionary<int, string> ExitToOutcome = new Dictionary<int, string>
    {
        [0] = "no_detection",
        [1] = "detection",
        [2] = "incomplete",
        [4] = "detection_incomplete",
        [5] = "nothing_scanned",
    };

    public static IReadOnlyList<string> Validate(
        ScanReport report, Guid expectedJobId, IReadOnlyList<string> requestedPaths, int exitCode,
        string expectedKind = "custom")
    {
        var problems = new List<string>();
        if (report.Schema != ScanReport.SchemaV2)
            problems.Add($"Unerwartetes Berichtsschema '{report.Schema}' (erwartet {ScanReport.SchemaV2}).");
        if (!Guid.TryParse(report.JobId, out var id) || id != expectedJobId)
            problems.Add($"Bericht gehört zu einem anderen Auftrag ('{report.JobId}', erwartet {expectedJobId}).");
        if (!report.Scope.Roots.SequenceEqual(requestedPaths))
            problems.Add("Die Pfade im Bericht stimmen nicht mit den angeforderten Pfaden überein.");
        if (report.Scope.Kind != expectedKind)
            problems.Add($"Scanart im Bericht ('{report.Scope.Kind}') ist nicht die angeforderte ('{expectedKind}').");
        if (!ExitToOutcome.TryGetValue(exitCode, out var expectedOutcome))
            problems.Add($"Exitcode {exitCode} ist für einen gültigen Bericht nicht zulässig.");
        else if (report.Outcome != expectedOutcome)
            problems.Add($"Exitcode {exitCode} passt nicht zum Ergebnis '{report.Outcome}'.");
        if (!report.Summary.IsConsistent)
            problems.Add("Die Zähler im Bericht sind widersprüchlich.");
        if (report.Summary.ObjectsTotal != report.Files.Count)
            problems.Add("Anzahl der Objekte stimmt nicht mit der Liste überein.");
        var completeExpected = report.Outcome is "detection" or "no_detection";
        if (report.Complete != completeExpected)
            problems.Add("'complete' widerspricht dem Ergebnis.");
        return problems;
    }
}
