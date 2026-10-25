using System.Text.Json;
using AXSafe.Client;

namespace AXSafe.Client.Tests;

/// <summary>
/// Echte Ende-zu-Ende-Prüfungen gegen die AXSafe-CLI (Befund 5, 2, 6, 7).
/// Pfad zur CLI: Umgebungsvariable AXSAFE_CLI, sonst target/debug/axsafe im Repo.
/// </summary>
public sealed class ClientTests : IDisposable
{
    private readonly string _tmp;

    public ClientTests()
    {
        _tmp = Path.Combine(Path.GetTempPath(), "axsafe-client-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tmp);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmp, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Cargo.toml")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Repository-Wurzel nicht gefunden");
    }

    private static string CliPath()
    {
        var env = Environment.GetEnvironmentVariable("AXSAFE_CLI");
        if (!string.IsNullOrEmpty(env)) return env;
        var exe = OperatingSystem.IsWindows() ? "axsafe.exe" : "axsafe";
        var p = Path.Combine(RepoRoot(), "target", "debug", exe);
        Assert.True(File.Exists(p), $"Vorbedingung: CLI fehlt unter {p} (vorher 'cargo build -p axsafe-cli' ausführen)");
        return p;
    }

    private AxsafeCliClient Client(string? reports = null) =>
        new(CliPath(), reports ?? Path.Combine(_tmp, "reports"), Path.Combine(RepoRoot(), "rules"));

    private string Folder(string name, params (string File, byte[] Data)[] files)
    {
        var d = Path.Combine(_tmp, name);
        Directory.CreateDirectory(d);
        foreach (var (f, data) in files) File.WriteAllBytes(Path.Combine(d, f), data);
        return d;
    }

    private static byte[] Eicar() =>
        System.Text.Encoding.ASCII.GetBytes("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    [Fact]
    public async Task Real_health_report_is_parsed_and_never_green_without_sensor()
    {
        var h = await Client().GetHealthAsync(useClamav: false, CancellationToken.None);
        Assert.NotNull(h);
        Assert.Equal(HealthView.Schema, h!.Schema);
        Assert.Equal("missing", h.Sensor!.State);
        Assert.Equal("missing", h.PrimaryProtection!.State);
        Assert.NotEqual(HealthColor.Green, HealthView.From(h).Color);
    }

    [Fact]
    public async Task Missing_cli_gives_unknown_health()
    {
        var c = new AxsafeCliClient(Path.Combine(_tmp, "gibt-es-nicht"), Path.Combine(_tmp, "r"), Path.Combine(RepoRoot(), "rules"));
        var h = await c.GetHealthAsync(useClamav: false, CancellationToken.None);
        Assert.Null(h);
        Assert.Equal(HealthColor.Gray, HealthView.From(h).Color);
    }

    [Fact]
    public async Task Scan_returns_validated_report_of_this_job()
    {
        var dir = Folder("a", ("brief.txt", "Hallo"u8.ToArray()));
        var r = await Client().ScanAsync(new[] { dir }, useClamav: false, CancellationToken.None);
        Assert.True(r.Success, r.Error);
        Assert.Equal(r.JobId, Guid.Parse(r.Report!.JobId));
        Assert.Equal(new[] { dir }, r.Report.Scope.Roots);
        Assert.Equal("no_detection", r.Report.Outcome);
        Assert.Contains(r.JobId.ToString("N"), r.ReportPath);
    }

    [Fact]
    public async Task Two_parallel_jobs_get_distinct_ids_and_own_reports()
    {
        var a = Folder("p1", ("x.txt", "eins"u8.ToArray()));
        var b = Folder("p2", ("y.txt", "zwei"u8.ToArray()), ("e.com", Eicar()));
        // Zwei Clients = zwei App-Instanzen mit demselben Berichtsordner.
        var reports = Path.Combine(_tmp, "shared-reports");
        var t1 = Client(reports).ScanAsync(new[] { a }, false, CancellationToken.None);
        var t2 = Client(reports).ScanAsync(new[] { b }, false, CancellationToken.None);
        var r = await Task.WhenAll(t1, t2);
        Assert.All(r, x => Assert.True(x.Success, x.Error));
        Assert.NotEqual(r[0].JobId, r[1].JobId);
        Assert.NotEqual(r[0].ReportPath, r[1].ReportPath);
        Assert.Equal(new[] { a }, r[0].Report!.Scope.Roots);
        Assert.Equal(new[] { b }, r[1].Report!.Scope.Roots);
        Assert.Equal("no_detection", r[0].Report!.Outcome);
        Assert.Equal("detection", r[1].Report!.Outcome);
    }

    [Fact]
    public async Task Failure_before_report_never_shows_old_report()
    {
        var reports = Path.Combine(_tmp, "old");
        Directory.CreateDirectory(reports);
        // Ein alter, gültig aussehender Bericht liegt bereits im Ordner.
        var dir = Folder("b", ("x.txt", "x"u8.ToArray()));
        var old = await Client(reports).ScanAsync(new[] { dir }, false, CancellationToken.None);
        Assert.True(old.Success, old.Error);
        // Neuer Auftrag scheitert vor der Berichtserzeugung (CLI nicht startbar).
        var broken = new AxsafeCliClient(Path.Combine(_tmp, "gibt-es-nicht"), reports, null);
        var r = await broken.ScanAsync(new[] { dir }, false, CancellationToken.None);
        Assert.False(r.Success);
        Assert.Null(r.Report);
        Assert.NotNull(r.Error);
    }

    [Fact]
    public async Task Reports_folder_that_is_a_file_is_a_controlled_error()
    {
        var notADir = Path.Combine(_tmp, "datei-statt-ordner");
        File.WriteAllText(notADir, "x");
        var dir = Folder("c", ("x.txt", "x"u8.ToArray()));
        var r = await Client(notADir).ScanAsync(new[] { dir }, false, CancellationToken.None);
        Assert.False(r.Success);
        Assert.Null(r.Report);
        Assert.Contains("Berichtsordner", r.Error);
    }

    [Fact]
    public async Task Cli_refusal_exit_3_is_error_without_report()
    {
        // Ungültiger Regelordner lässt die CLI zwar scannen; Exit 3 entsteht
        // bei einem unzulässigen Berichtsziel. Hier: Berichtsordner schreibgeschützt
        // ist als root nicht erzwingbar, daher direkter Aufruf mit belegtem Ziel.
        var dir = Folder("d", ("x.txt", "x"u8.ToArray()));
        var psi = new System.Diagnostics.ProcessStartInfo(CliPath())
        {
            RedirectStandardError = true,
            RedirectStandardOutput = true,
        };
        foreach (var a in new[] { "scan", "--no-clamav", "--json", Path.Combine(dir, "x.txt"), dir })
            psi.ArgumentList.Add(a);
        using var p = System.Diagnostics.Process.Start(psi)!;
        await p.WaitForExitAsync();
        Assert.Equal(3, p.ExitCode);
        Assert.False(ReportValidator.ExitToOutcome.ContainsKey(3), "Exit 3 darf nie als Bericht gelten");
    }

    [Fact]
    public async Task Empty_folder_is_nothing_scanned_and_valid()
    {
        var dir = Folder("leer");
        var r = await Client().ScanAsync(new[] { dir }, false, CancellationToken.None);
        Assert.True(r.Success, r.Error);
        Assert.Equal(5, r.ExitCode);
        Assert.Equal("nothing_scanned", r.Report!.Outcome);
        Assert.False(r.Report.Complete);
    }

    [Fact]
    public async Task Engines_report_test_only_rules()
    {
        var e = await Client().GetEnginesAsync(useClamav: false, CancellationToken.None);
        Assert.NotNull(e);
        var y = Assert.Single(e!);
        Assert.True(y.Ready);
        Assert.True(y.TestOnly);
        Assert.Equal("keine (nur Rohbytes)", y.ContainerLabel);
        // P02: YARA-X läuft im abgeschotteten Worker, Nachweis per Probe.
        Assert.Equal("sandboxed_worker", y.Isolation.Kind);
        Assert.True(y.Isolation.Enforced, y.Isolation.Detail);
        Assert.Equal("abgeschotteter Worker (nachgewiesen)", y.IsolationLabel);
    }

    // --- Validierung mit gezielt verfälschten Berichten -------------------

    private static ScanReport Sample(Guid id, string root) => new()
    {
        Schema = ScanReport.SchemaV2,
        JobId = id.ToString(),
        Outcome = "no_detection",
        Complete = true,
        Scope = new Scope { Roots = new() { root } },
        Summary = new Summary { ObjectsTotal = 1, ObjectsRead = 1, NoDetectionComplete = 1 },
        Files = new() { new FileResult { Path = root, Status = "no_detection" } },
    };

    [Fact]
    public void Validator_accepts_consistent_report()
    {
        var id = Guid.NewGuid();
        Assert.Empty(ReportValidator.Validate(Sample(id, "/x"), id, new[] { "/x" }, 0));
    }

    [Theory]
    [InlineData("schema")]
    [InlineData("job")]
    [InlineData("roots")]
    [InlineData("exit")]
    [InlineData("exit-mismatch")]
    [InlineData("counts")]
    [InlineData("complete")]
    public void Validator_rejects_foreign_or_inconsistent_report(string tamper)
    {
        var id = Guid.NewGuid();
        var r = Sample(id, "/x");
        var exit = 0;
        var roots = new[] { "/x" };
        switch (tamper)
        {
            case "schema": r.Schema = "axsafe.scan-report/1"; break;
            case "job": r.JobId = Guid.NewGuid().ToString(); break;
            case "roots": roots = new[] { "/y" }; break;
            case "exit": exit = 3; break;
            case "exit-mismatch": exit = 1; break;
            case "counts": r.Summary.WithDetection = 5; break;
            case "complete": r.Complete = false; break;
        }
        Assert.NotEmpty(ReportValidator.Validate(r, id, roots, exit));
    }

    [Fact]
    public void Real_report_json_roundtrips_into_model()
    {
        var json = """
        {"schema":"axsafe.scan-report/2","job_id":"0b7c3f7a-3a52-4c64-9a0e-6c2b9e1f4d11","outcome":"detection_incomplete",
         "detection":"Malicious","complete":false,"cancelled":false,"job_gaps":[],
         "scope":{"roots":["/d"],"engines":[],"excluded":[]},
         "summary":{"objects_total":1,"objects_read":1,"bytes_read":68,"with_detection":1,"incomplete":1,"detection_and_incomplete":1,"no_detection_complete":0},
         "files":[{"path":"/d/e.com","object_type":"file","detection":"Malicious","status":"detection_incomplete",
                   "gaps":[{"state":"Error","reason":"engine_error","source":"clamav","detail":"x"}],"engines":[]}]}
        """;
        var r = JsonSerializer.Deserialize<ScanReport>(json)!;
        Assert.Equal("Fund vorhanden; zusätzliche Prüflücke", r.Files[0].StatusLabel);
        Assert.Contains("Engine-Fehler", r.Files[0].Details);
        Assert.Empty(ReportValidator.Validate(r, Guid.Parse(r.JobId), new[] { "/d" }, 4));
    }
}

/// <summary>Protokoll axsafe.ipc/1 auf Client-Seite (plattformneutral).</summary>
public sealed class ServiceProtocolTests
{
    [Fact]
    public void Request_frame_has_length_prefix_and_no_identity_fields()
    {
        var frame = ServiceClient.Encode(7, "0123456789abcdef0123456789abcdef", ServiceClient.ScanStart(new[] { @"C:\x" }, true));
        var len = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(frame);
        Assert.Equal(frame.Length - 4, (int)len);
        var json = System.Text.Encoding.UTF8.GetString(frame, 4, frame.Length - 4);
        Assert.Contains("\"protocol\":\"axsafe.ipc/1\"", json);
        Assert.Contains("\"seq\":7", json);
        Assert.Contains("\"type\":\"scan_start\"", json);
        foreach (var forbidden in new[] { "sid", "session", "pid", "user" })
            Assert.DoesNotContain(forbidden, json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Oversized_response_length_is_rejected_before_allocation()
    {
        var bytes = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes, ServiceClient.MaxResponseBytes + 1);
        await Assert.ThrowsAsync<InvalidDataException>(() => ServiceClient.ReadResponseAsync(new MemoryStream(bytes), CancellationToken.None));
    }

    [Fact]
    public async Task Probe_without_service_never_reports_ready()
    {
        if (Environment.GetEnvironmentVariable("AXSAFE_SERVICE_TEST") == "1") return; // Dienst läuft absichtlich (Dienst-Job)
        var s = await ServiceClient.ProbeAsync(CancellationToken.None, 500);
        Assert.NotEqual(ServiceState.Bereit, s.State);
        Assert.False(string.IsNullOrEmpty(s.Detail));
    }
}

/// <summary>
/// Gegen den echten Dienst (nur im Windows-Dienst-Job, Filter Kategorie=Dienst).
/// Scheitert laut, wenn der Dienst fehlt.
/// </summary>
[Trait("Kategorie", "Dienst")]
public sealed class LiveServiceTests
{
    [Fact]
    public async Task Status_scan_and_report_through_real_service()
    {
        var s = await ServiceClient.ProbeAsync(CancellationToken.None, 5000);
        Assert.True(s.State is ServiceState.Bereit or ServiceState.Startet, $"{s.State}: {s.Detail}");
        var dir = Path.Combine(Path.GetTempPath(), "axsafe-dienst-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "brief.txt"), "harmlos");
        try
        {
            Assert.True(OperatingSystem.IsWindows(), "Dienst-Tests nur unter Windows");
#pragma warning disable CA1416
            using var c = ServiceClient.Connect(5000);
#pragma warning restore CA1416
            var r = await c.CallAsync(ServiceClient.ScanStart(new[] { dir }, false), CancellationToken.None);
            Assert.True(r["ok"]!.GetValue<bool>(), r.ToJsonString());
            var job = (string)r["result"]!["job_id"]!;
            string state;
            var t = DateTime.UtcNow;
            do
            {
                await Task.Delay(200);
                var j = await c.CallAsync(ServiceClient.Job(job), CancellationToken.None);
                state = (string)j["result"]!["state"]!;
            } while (state is "queued" or "running" && DateTime.UtcNow - t < TimeSpan.FromMinutes(2));
            Assert.Equal("finished", state);
            var rep = await c.CallAsync(ServiceClient.Report(job), CancellationToken.None);
            var report = rep["result"]!["report"]!.Deserialize<ScanReport>()!;
            Assert.Equal(job, report.JobId);
            Assert.Equal("no_detection", report.Outcome);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}

/// <summary>T-019: Fehlende oder kaputte Antworten erzeugen nie einen grünen Status.</summary>
public sealed class HealthViewTests
{
    private static HealthReport Full(string overall, string state) => new()
    {
        Schema = HealthView.Schema,
        Overall = overall,
        Summary = "x",
        Scanner = new() { State = state },
        Sensor = new() { State = state },
        Policy = new() { State = state },
        Definitions = new() { State = state },
        PrimaryProtection = new() { State = state },
        Service = new() { State = state },
    };

    [Fact]
    public void Missing_or_invalid_answer_is_unknown_never_green()
    {
        Assert.Equal(HealthColor.Gray, HealthView.From(null).Color);
        Assert.Equal(HealthColor.Gray, HealthView.From(HealthView.Parse("{ kaputt")).Color);
        Assert.Equal(HealthColor.Gray, HealthView.From(HealthView.Parse("{\"overall\":\"geschuetzt\"}")).Color);
        var partial = Full("geschuetzt", "ready");
        partial.Sensor = null;
        Assert.Equal(HealthColor.Gray, HealthView.From(partial).Color);
    }

    [Fact]
    public void Green_only_when_everything_is_ready()
    {
        Assert.Equal(HealthColor.Green, HealthView.From(Full("geschuetzt", "ready")).Color);
        var r = Full("geschuetzt", "ready");
        r.Sensor!.State = "missing";
        Assert.NotEqual(HealthColor.Green, HealthView.From(r).Color);
        Assert.Equal(HealthColor.Amber, HealthView.From(Full("eingeschraenkt", "degraded")).Color);
        Assert.Equal(HealthColor.Red, HealthView.From(Full("nicht_betriebsbereit", "missing")).Color);
        Assert.Equal(HealthColor.Gray, HealthView.From(Full("etwas_neues", "ready")).Color);
    }
}
