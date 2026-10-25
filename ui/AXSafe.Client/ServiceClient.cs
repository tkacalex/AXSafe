using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AXSafe.Client;

/// <summary>Zustand des AXSafe-Dienstes, wie die Oberfläche ihn anzeigt.</summary>
public enum ServiceState
{
    /// <summary>Dienst ist nicht installiert.</summary>
    Fehlt,
    /// <summary>Dienst startet oder prüft gerade seine Engines.</summary>
    Startet,
    /// <summary>Dienst hat Bereitschaft und Engines bestätigt.</summary>
    Bereit,
    /// <summary>Dienst antwortet fehlerhaft oder läuft ohne Pipe.</summary>
    Gestoert,
    /// <summary>Dienst gestoppt, ausgelastet oder Zugriff verweigert.</summary>
    NichtErreichbar,
}

public sealed record ServiceStatus(ServiceState State, string Detail, JsonObject? Result)
{
    public string Label => State switch
    {
        ServiceState.Fehlt => "Dienst fehlt",
        ServiceState.Startet => "Dienst startet",
        ServiceState.Bereit => "Dienst bereit",
        ServiceState.Gestoert => "Dienst gestört",
        _ => "Dienst nicht erreichbar",
    };
}

/// <summary>
/// Client für <c>axsafe.ipc/1</c> über <c>\\.\pipe\AXSafe.v1</c>.
/// Öffnet die Pipe mit genau den Rechten, die die Pipe-DACL interaktiven
/// Benutzern gibt, und erlaubt dem Dienst Impersonation (er liest Dateien
/// mit den Rechten dieses Benutzers). Identität wird NICHT mitgeschickt –
/// der Dienst ermittelt sie aus dem Token.
/// </summary>
public sealed class ServiceClient : IDisposable
{
    public const string PipeName = "AXSafe.v1";
    public const string Protocol = "axsafe.ipc/1";
    public const int MaxResponseBytes = 16 * 1024 * 1024;

    private readonly Stream _stream;
    private ulong _seq;

    public ServiceClient(Stream connected) => _stream = connected;

    /// <summary>Verbindet zur lokalen Dienst-Pipe (nur Windows).</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static ServiceClient Connect(int timeoutMs = 3000)
    {
        var rights = PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes
                     | PipeAccessRights.WriteAttributes | PipeAccessRights.ReadPermissions | PipeAccessRights.Synchronize;
        var pipe = new NamedPipeClientStream(".", PipeName, rights, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Impersonation, HandleInheritability.None);
        try
        {
            pipe.Connect(timeoutMs);
        }
        catch
        {
            pipe.Dispose();
            throw;
        }
        return new ServiceClient(pipe);
    }

    public static string NewNonce() => Guid.NewGuid().ToString("N");

    /// <summary>Kodiert eine Anfrage als Rahmen (Länge + JSON).</summary>
    public static byte[] Encode(ulong seq, string nonce, JsonObject body)
    {
        var req = new JsonObject
        {
            ["protocol"] = Protocol,
            ["seq"] = seq,
            ["nonce"] = nonce,
            ["body"] = body,
        };
        var json = JsonSerializer.SerializeToUtf8Bytes(req);
        var frame = new byte[json.Length + 4];
        BinaryPrimitives.WriteUInt32LittleEndian(frame, (uint)json.Length);
        json.CopyTo(frame, 4);
        return frame;
    }

    /// <summary>Liest eine Antwort; lehnt übergroße Längen vor dem Allokieren ab.</summary>
    public static async Task<JsonObject> ReadResponseAsync(Stream s, CancellationToken ct)
    {
        var len = new byte[4];
        await s.ReadExactlyAsync(len, ct).ConfigureAwait(false);
        var n = BinaryPrimitives.ReadUInt32LittleEndian(len);
        if (n == 0 || n > MaxResponseBytes)
            throw new InvalidDataException($"Antwortlänge {n} unzulässig");
        var buf = new byte[n];
        await s.ReadExactlyAsync(buf, ct).ConfigureAwait(false);
        return JsonNode.Parse(buf) as JsonObject ?? throw new InvalidDataException("Antwort ist kein Objekt");
    }

    public async Task<JsonObject> CallAsync(JsonObject body, CancellationToken ct)
    {
        _seq++;
        var frame = Encode(_seq, NewNonce(), body);
        await _stream.WriteAsync(frame, ct).ConfigureAwait(false);
        await _stream.FlushAsync(ct).ConfigureAwait(false);
        var resp = await ReadResponseAsync(_stream, ct).ConfigureAwait(false);
        if ((string?)resp["protocol"] != Protocol)
            throw new InvalidDataException("Antwort mit unbekanntem Protokoll");
        if ((ulong?)resp["seq"] is ulong s && s != _seq && s != 0)
            throw new InvalidDataException($"Antwort gehört zu Anfrage {s}, erwartet {_seq}");
        return resp;
    }

    public static JsonObject Status() => new() { ["type"] = "status" };
    public static JsonObject ScanStart(IEnumerable<string> paths, bool useClamav) => new()
    {
        ["type"] = "scan_start",
        ["paths"] = new JsonArray(paths.Select(p => (JsonNode)JsonValue.Create(p)!).ToArray()),
        ["use_clamav"] = useClamav,
    };
    public static JsonObject ScanCancel(string jobId) => new() { ["type"] = "scan_cancel", ["job_id"] = jobId };
    public static JsonObject Job(string jobId) => new() { ["type"] = "job", ["job_id"] = jobId };
    public static JsonObject Report(string jobId) => new() { ["type"] = "report", ["job_id"] = jobId };

    /// <summary>
    /// Ermittelt den Dienstzustand. „Bereit“ nur, wenn der Dienst selbst
    /// Bereitschaft UND geprüfte Engines meldet.
    /// </summary>
    public static async Task<ServiceStatus> ProbeAsync(CancellationToken ct, int timeoutMs = 3000)
    {
        if (!OperatingSystem.IsWindows())
            return new(ServiceState.Fehlt, "Der AXSafe-Dienst existiert nur unter Windows.", null);
        ServiceClient c;
        try
        {
            c = Connect(timeoutMs);
        }
        catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
        {
            var scm = QueryScm();
            return scm switch
            {
                "missing" => new(ServiceState.Fehlt, "Dienst AXSafeService ist nicht installiert. Prüfungen laufen lokal mit Benutzerrechten.", null),
                "start_pending" => new(ServiceState.Startet, "Dienst startet …", null),
                "running" => new(ServiceState.Gestoert, $"Dienst läuft, aber die Pipe antwortet nicht: {ex.Message}", null),
                "stopped" => new(ServiceState.NichtErreichbar, "Dienst ist gestoppt.", null),
                _ => new(ServiceState.NichtErreichbar, $"Dienst nicht erreichbar: {ex.Message}", null),
            };
        }
        using (c)
        {
            try
            {
                var r = await c.CallAsync(Status(), ct).ConfigureAwait(false);
                if (r["ok"]?.GetValue<bool>() != true)
                    return new(ServiceState.Gestoert, $"Dienst lehnt ab: {r["error"]?["message"]}", null);
                var result = r["result"] as JsonObject;
                var eng = (string?)result?["engines"]?["state"];
                if ((string?)result?["service"] != "bereit")
                    return new(ServiceState.Gestoert, "Dienst meldet keine Bereitschaft.", result);
                return eng == "geprüft"
                    ? new(ServiceState.Bereit, $"Dienst bereit · {result?["file_access"]}", result)
                    : new(ServiceState.Startet, "Dienst prüft seine Engines …", result);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or OperationCanceledException)
            {
                return new(ServiceState.Gestoert, $"Kommunikation gestört: {ex.Message}", null);
            }
        }
    }

    /// <summary>Fragt den Dienststatus über sc.exe (fester Systempfad) ab.</summary>
    private static string QueryScm()
    {
        try
        {
            var sc = Path.Combine(Environment.SystemDirectory, "sc.exe");
            var psi = new ProcessStartInfo(sc) { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            psi.ArgumentList.Add("query");
            psi.ArgumentList.Add("AXSafeService");
            using var p = Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(3000)) { p.Kill(); return "unknown"; }
            if (p.ExitCode == 1060) return "missing";
            if (o.Contains("START_PENDING")) return "start_pending";
            if (o.Contains("RUNNING")) return "running";
            if (o.Contains("STOPPED")) return "stopped";
            return "unknown";
        }
        catch (Exception)
        {
            return "unknown";
        }
    }

    public void Dispose() => _stream.Dispose();
}
