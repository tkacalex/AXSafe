using System.Text.Json;
using System.Text.Json.Serialization;

namespace AXSafe.Client;

/// <summary>Betriebszustand laut <c>axsafe zustand --json</c> (AXS-019).</summary>
public sealed class HealthReport
{
    [JsonPropertyName("schema")] public string Schema { get; set; } = "";
    [JsonPropertyName("overall")] public string Overall { get; set; } = "";
    [JsonPropertyName("summary")] public string Summary { get; set; } = "";
    [JsonPropertyName("scanner")] public HealthComponent? Scanner { get; set; }
    [JsonPropertyName("sensor")] public HealthComponent? Sensor { get; set; }
    [JsonPropertyName("policy")] public HealthComponent? Policy { get; set; }
    [JsonPropertyName("definitions")] public HealthComponent? Definitions { get; set; }
    [JsonPropertyName("primary_protection")] public HealthComponent? PrimaryProtection { get; set; }
    [JsonPropertyName("service")] public HealthComponent? Service { get; set; }
}

public sealed class HealthComponent
{
    [JsonPropertyName("state")] public string State { get; set; } = "";
    [JsonPropertyName("detail")] public string Detail { get; set; } = "";
}

/// <summary>Anzeigefarbe des Gesamtzustands.</summary>
public enum HealthColor { Green, Amber, Red, Gray }

/// <summary>
/// Abbildung auf die Anzeige. Grün NUR bei einem gültigen Bericht mit
/// Gesamtzustand „geschuetzt“ UND allen Bestandteilen „ready“. Fehlende,
/// unlesbare oder unbekannte Antworten ergeben „Unbekannt“ (grau), nie grün.
/// </summary>
public static class HealthView
{
    public const string Schema = "axsafe.health/1";

    public static (string Label, HealthColor Color, string Detail) From(HealthReport? h)
    {
        if (h is null || h.Schema != Schema)
            return ("Unbekannt", HealthColor.Gray, "Betriebszustand nicht abfragbar – keine Aussage über den Schutz");
        var parts = new[] { h.Scanner, h.Sensor, h.Policy, h.Definitions, h.PrimaryProtection, h.Service };
        if (parts.Any(p => p is null))
            return ("Unbekannt", HealthColor.Gray, "Betriebszustand unvollständig – keine Aussage über den Schutz");
        return h.Overall switch
        {
            "geschuetzt" when parts.All(p => p!.State == "ready") => ("Geschützt", HealthColor.Green, h.Summary),
            "eingeschraenkt" => ("Eingeschränkt", HealthColor.Amber, h.Summary),
            "nicht_betriebsbereit" => ("Nicht betriebsbereit", HealthColor.Red, h.Summary),
            _ => ("Unbekannt", HealthColor.Gray, string.IsNullOrEmpty(h.Summary) ? "Zustand unbekannt" : h.Summary),
        };
    }

    public static HealthReport? Parse(string json)
    {
        try { return JsonSerializer.Deserialize<HealthReport>(json); }
        catch (JsonException) { return null; }
    }

    public static string StateText(string s) => s switch
    {
        "ready" => "bereit",
        "degraded" => "eingeschränkt",
        "missing" => "fehlt",
        _ => "unbekannt",
    };
}
