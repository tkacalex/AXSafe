using System.Text.Json.Serialization;

namespace AXSafe.Client;

// Abbild des Berichtsschemas "axsafe.scan-report/2" (crates/axsafe-core/src/report.rs).
// Fund (detection) und Vollständigkeit (gaps/complete/outcome) sind getrennt.

public sealed class ScanReport
{
    public const string SchemaV2 = "axsafe.scan-report/2";

    [JsonPropertyName("schema")] public string Schema { get; set; } = "";
    [JsonPropertyName("job_id")] public string JobId { get; set; } = "";
    [JsonPropertyName("axsafe_version")] public string AxsafeVersion { get; set; } = "";
    [JsonPropertyName("started_utc")] public string StartedUtc { get; set; } = "";
    [JsonPropertyName("finished_utc")] public string FinishedUtc { get; set; } = "";
    [JsonPropertyName("duration_ms")] public long DurationMs { get; set; }
    [JsonPropertyName("scope")] public Scope Scope { get; set; } = new();
    [JsonPropertyName("outcome")] public string Outcome { get; set; } = "";
    [JsonPropertyName("detection")] public string Detection { get; set; } = "NoDetection";
    [JsonPropertyName("complete")] public bool Complete { get; set; }
    [JsonPropertyName("cancelled")] public bool Cancelled { get; set; }
    [JsonPropertyName("job_gaps")] public List<Gap> JobGaps { get; set; } = new();
    [JsonPropertyName("summary")] public Summary Summary { get; set; } = new();
    [JsonPropertyName("files")] public List<FileResult> Files { get; set; } = new();
}

public sealed class Summary
{
    [JsonPropertyName("objects_total")] public long ObjectsTotal { get; set; }
    [JsonPropertyName("objects_read")] public long ObjectsRead { get; set; }
    [JsonPropertyName("bytes_read")] public long BytesRead { get; set; }
    [JsonPropertyName("with_detection")] public long WithDetection { get; set; }
    [JsonPropertyName("incomplete")] public long Incomplete { get; set; }
    [JsonPropertyName("detection_and_incomplete")] public long DetectionAndIncomplete { get; set; }
    [JsonPropertyName("no_detection_complete")] public long NoDetectionComplete { get; set; }

    /// <summary>Dokumentierte Zählinvariante aus report.rs.</summary>
    public bool IsConsistent =>
        WithDetection + Incomplete - DetectionAndIncomplete + NoDetectionComplete == ObjectsTotal
        && DetectionAndIncomplete <= Math.Min(WithDetection, Incomplete);
}

public sealed class Scope
{
    [JsonPropertyName("roots")] public List<string> Roots { get; set; } = new();
    [JsonPropertyName("engines")] public List<EngineInfo> Engines { get; set; } = new();
    [JsonPropertyName("excluded")] public List<ExcludedObject> Excluded { get; set; } = new();
}

public sealed class ExcludedObject
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("reason")] public string Reason { get; set; } = "";
}

public sealed class EngineInfo
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("engine_version")] public string EngineVersion { get; set; } = "";
    [JsonPropertyName("content_version")] public string ContentVersion { get; set; } = "";
    [JsonPropertyName("health")] public EngineHealth Health { get; set; } = new();
    [JsonPropertyName("license")] public string License { get; set; } = "";
    [JsonPropertyName("content_kind")] public string ContentKind { get; set; } = "unknown";
    [JsonPropertyName("content_note")] public string ContentNote { get; set; } = "";
    [JsonPropertyName("inspects_contents_of")] public List<string> InspectsContentsOf { get; set; } = new();

    [JsonIgnore] public bool Ready => Health.State == "ready";
    [JsonIgnore] public bool TestOnly => ContentKind == "test_only";
    [JsonIgnore] public string ReadinessLabel => Ready ? "bereit" : "nicht verfügbar";
    [JsonIgnore] public string ContentLabel => Texts.ContentKind(ContentKind);
    [JsonIgnore]
    public string ContainerLabel => InspectsContentsOf.Count == 0
        ? "keine (nur Rohbytes)"
        : string.Join(", ", InspectsContentsOf);
}

public sealed class EngineHealth
{
    [JsonPropertyName("state")] public string State { get; set; } = "unavailable";
    [JsonPropertyName("reason")] public string? Reason { get; set; }
}

public sealed class Gap
{
    [JsonPropertyName("state")] public string State { get; set; } = "Error";
    [JsonPropertyName("reason")] public string Reason { get; set; } = "";
    [JsonPropertyName("source")] public string Source { get; set; } = "";
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
}

public sealed class FileResult
{
    [JsonPropertyName("path")] public string Path { get; set; } = "";
    [JsonPropertyName("object_type")] public string ObjectType { get; set; } = "";
    [JsonPropertyName("detection")] public string Detection { get; set; } = "NoDetection";
    [JsonPropertyName("gaps")] public List<Gap> Gaps { get; set; } = new();
    [JsonPropertyName("status")] public string Status { get; set; } = "incomplete";
    [JsonPropertyName("size")] public long? Size { get; set; }
    [JsonPropertyName("engines")] public List<EngineOutcome> Engines { get; set; } = new();

    /// <summary>Status als Text, nie nur als Farbe (AXS-090).</summary>
    [JsonIgnore] public string StatusLabel => Texts.ObjectStatus(Status);

    [JsonIgnore]
    public string Details
    {
        get
        {
            var parts = new List<string>();
            foreach (var e in Engines)
                foreach (var d in e.Detections)
                    parts.Add($"Fund: {d.Name}{(d.TestSignature ? " (Testsignatur)" : "")} · {e.Engine}");
            foreach (var g in Gaps)
                parts.Add($"Lücke: {Texts.GapReason(g.Reason)} ({g.Source}) – {g.Detail}");
            return string.Join("\n", parts);
        }
    }
}

public sealed class EngineOutcome
{
    [JsonPropertyName("engine")] public string Engine { get; set; } = "";
    [JsonPropertyName("verdict")] public string Verdict { get; set; } = "Error";
    [JsonPropertyName("detections")] public List<Detection> Detections { get; set; } = new();
}

public sealed class Detection
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("test_signature")] public bool TestSignature { get; set; }
}

/// <summary>Deutsche Anzeigetexte zu Zuständen aus dem Bericht.</summary>
public static class Texts
{
    public static string ObjectStatus(string s) => s switch
    {
        "detection" => "Fund",
        "detection_incomplete" => "Fund vorhanden; zusätzliche Prüflücke",
        "no_detection" => "Ohne Fund",
        "incomplete" => "Nicht vollständig geprüft",
        _ => "Unbekannt",
    };

    public static string Outcome(string o) => o switch
    {
        "detection" => "Fund – AXSafe hat nichts verändert (Vorversion meldet nur).",
        "detection_incomplete" => "Fund vorhanden; zusätzlich wurden Teile nicht vollständig geprüft.",
        "no_detection" => "Nichts erkannt – nur im geprüften Umfang, kein Beweis für Harmlosigkeit.",
        "incomplete" => "Unvollständig: Einige Objekte oder Engines konnten nicht vollständig prüfen. Kein Fund im geprüften Teil.",
        "nothing_scanned" => "Keine prüfbaren Objekte – es wurde nichts geprüft.",
        _ => "Unbekanntes Ergebnis.",
    };

    public static string ContentKind(string k) => k switch
    {
        "test_only" => "nur Funktionstest-Regeln",
        "production" => "produktive Regeln",
        "official_signatures" => "offizielle Signaturen",
        "custom_signatures" => "eigene Signaturen",
        _ => "unbekannt",
    };

    public static string GapReason(string r) => r switch
    {
        "engine_unavailable" => "Engine nicht verfügbar",
        "engine_error" => "Engine-Fehler",
        "engine_timeout" => "Zeitlimit",
        "output_limit" => "Ausgabe zu groß",
        "content_not_inspected" => "Containerinhalt nicht geprüft",
        "encrypted" => "verschlüsselt",
        "engine_limit_exceeded" => "Engine-Grenzwert",
        "size_limit" => "Datei zu groß",
        "depth_limit" => "Verzeichnistiefe",
        "link_not_followed" => "Link nicht verfolgt",
        "not_regular_file" => "keine reguläre Datei",
        "access_denied" => "kein Zugriff",
        "io_error" => "Lesefehler",
        "changed_during_scan" => "während der Prüfung geändert",
        "cancelled" => "abgebrochen",
        "no_engine" => "keine Engine",
        _ => r,
    };
}
