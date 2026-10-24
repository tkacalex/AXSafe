using System.Text.Json.Serialization;

namespace AXSafe.Desktop.Models;

// Abbild des Berichtsschemas "axsafe.scan-report/1" aus axsafe-core (report.rs).
// Die Oberfläche zeigt ausschließlich Werte aus diesem Bericht an.

public sealed class ScanReport
{
    [JsonPropertyName("schema")] public string Schema { get; set; } = "";
    [JsonPropertyName("job_id")] public string JobId { get; set; } = "";
    [JsonPropertyName("axsafe_version")] public string AxsafeVersion { get; set; } = "";
    [JsonPropertyName("started_utc")] public string StartedUtc { get; set; } = "";
    [JsonPropertyName("finished_utc")] public string FinishedUtc { get; set; } = "";
    [JsonPropertyName("duration_ms")] public long DurationMs { get; set; }
    [JsonPropertyName("complete")] public bool Complete { get; set; }
    [JsonPropertyName("cancelled")] public bool Cancelled { get; set; }
    [JsonPropertyName("overall")] public string Overall { get; set; } = "Error";
    [JsonPropertyName("summary")] public Summary Summary { get; set; } = new();
    [JsonPropertyName("scope")] public Scope Scope { get; set; } = new();
    [JsonPropertyName("files")] public List<FileResult> Files { get; set; } = new();
}

public sealed class Summary
{
    [JsonPropertyName("objects")] public long Objects { get; set; }
    [JsonPropertyName("bytes_read")] public long BytesRead { get; set; }
    [JsonPropertyName("detections")] public long Detections { get; set; }
    [JsonPropertyName("incomplete")] public long Incomplete { get; set; }
    [JsonPropertyName("no_detection")] public long NoDetection { get; set; }
}

public sealed class Scope
{
    [JsonPropertyName("roots")] public List<string> Roots { get; set; } = new();
    [JsonPropertyName("engines")] public List<EngineInfo> Engines { get; set; } = new();
}

public sealed class EngineInfo
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("engine_version")] public string EngineVersion { get; set; } = "";
    [JsonPropertyName("content_version")] public string ContentVersion { get; set; } = "";
    [JsonPropertyName("health")] public EngineHealth Health { get; set; } = new();
    [JsonPropertyName("license")] public string License { get; set; } = "";
}

public sealed class EngineHealth
{
    [JsonPropertyName("state")] public string State { get; set; } = "unavailable";
    [JsonPropertyName("reason")] public string? Reason { get; set; }
}

public sealed class FileResult
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("verdict")] public string Verdict { get; set; } = "Error";
    [JsonPropertyName("size")] public long? Size { get; set; }
    [JsonPropertyName("sha256")] public string? Sha256 { get; set; }
    [JsonPropertyName("notes")] public List<string> Notes { get; set; } = new();
    [JsonPropertyName("engines")] public List<EngineOutcome> Engines { get; set; } = new();

    /// <summary>Kurzer deutscher Status, nie nur Farbe (AXS-090).</summary>
    public string VerdictLabel => VerdictText.Label(Verdict);

    public string Details
    {
        get
        {
            var parts = new List<string>();
            foreach (var e in Engines)
            {
                foreach (var d in e.Detections)
                    parts.Add($"{d.Name}{(d.TestSignature ? " (Testsignatur)" : "")} · {e.Engine}");
                if (!string.IsNullOrWhiteSpace(e.Note)) parts.Add($"{e.Engine}: {e.Note}");
            }
            parts.AddRange(Notes);
            return string.Join("\n", parts);
        }
    }
}

public sealed class EngineOutcome
{
    [JsonPropertyName("engine")] public string Engine { get; set; } = "";
    [JsonPropertyName("verdict")] public string Verdict { get; set; } = "Error";
    [JsonPropertyName("note")] public string? Note { get; set; }
    [JsonPropertyName("detections")] public List<Detection> Detections { get; set; } = new();
}

public sealed class Detection
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("test_signature")] public bool TestSignature { get; set; }
}

public static class VerdictText
{
    public static string Label(string verdict) => verdict switch
    {
        "Malicious" => "Schädlich",
        "Suspicious" => "Verdächtig",
        "PUA" => "PUA",
        "NoDetection" => "Ohne Fund",
        "Unsupported" => "Nicht geprüft",
        "Encrypted" => "Verschlüsselt",
        "AccessDenied" => "Kein Zugriff",
        "Timeout" => "Zeitlimit",
        "ChangedDuringScan" => "Geändert",
        _ => "Fehler",
    };

    public static bool IsDetection(string v) => v is "Malicious" or "Suspicious" or "PUA";
}
