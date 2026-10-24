using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using AXSafe.Desktop.Models;
using AXSafe.Desktop.Services;
using Microsoft.Win32;

namespace AXSafe.Desktop;

/// <summary>
/// Hauptfenster. Grundsätze (AXS-087, AXS-089):
/// keine festen Beispielzähler, kein grüner Gesamtstatus ohne belegte
/// Schutzpipeline, nicht vorhandene Funktionen sichtbar deaktiviert und erklärt.
/// </summary>
public partial class MainWindow : Window
{
    private readonly AxsafeCli _cli = new();
    private CancellationTokenSource? _scanCts;

    public sealed record ModuleState(string Name, string State, Brush Brush);

    private sealed record InfoPage(string Title, string State, string Now, string Needed, string Limit);

    private static readonly Dictionary<string, InfoPage> Pages = new()
    {
        ["realtime"] = new("Echtzeitschutz", "Nicht verfügbar · geplant in Phase P08",
            "AXSafe prüft Dateien in dieser Vorversion nur, wenn du einen Scan startest. Es gibt noch keinen Dateisystemfilter.",
            "Ein minimaler, regulär signierter Windows-Minifilter mit User-Mode-Scanworker, getesteter Fehlerpolicy, Recovery und Microsoft-Treibersignierung (AXS-053 bis AXS-060).",
            "Ein Dateiwatcher allein kann eine Ausführung nicht rechtzeitig verhindern. AXSafe wird so etwas nie als Echtzeitschutz ausgeben."),
        ["ransomware"] = new("Ransomware-Schutz", "Nicht verfügbar · geplant in Phase P09",
            "Noch keine Schreibkontrolle und kein Versionsspeicher vorhanden.",
            "Korrelation von Prozess und Änderungsrate, getestete Schreibsperren, begrenzter Versionsspeicher und bytegenaue Wiederherstellungstests (AXS-061 bis AXS-066).",
            "Rollback funktioniert nur mit vorhandenen Originalen und schützt nicht vor bereits abgeflossenen Daten. Unabhängige Backups bleiben nötig."),
        ["network"] = new("Firewall & Netzwerk", "Nicht verfügbar · geplant in Phase P10",
            "AXSafe setzt keine eigenen Netzwerkfilter und liest den Windows-Firewall-Zustand noch nicht aus.",
            "Anzeige des Windows-Firewall-Zustands mit klarer Quellenangabe und gezielte WFP-Filter mit IPv4/IPv6/VPN-Tests (AXS-068, AXS-069).",
            "Verbindungsfilter entschlüsseln kein HTTPS. AXSafe installiert keine eigene Root-CA."),
        ["web"] = new("Web & Phishing", "Nicht verfügbar · geplant in Phase P10",
            "Keine Browsererweiterung und keine URL-Reputation vorhanden.",
            "Browsererweiterung mit minimalen Rechten und lizenzierter Reputation; Anhangprüfung für lokal gespeicherte E-Mail-Anhänge (AXS-067, AXS-070).",
            "'Unbekannt' ist kein Vertrauensbeweis. Ohne echte Postfachintegration heißt die Funktion Anhangprüfung, nicht E-Mail-Schutz."),
        ["quarantine"] = new("Quarantäne", "Nicht verfügbar · geplant in Phase P05",
            "Funde werden nur gemeldet. Es wird nichts verschoben oder gelöscht.",
            "Authentifiziert verschlüsselte Quarantäne mit transaktionalem Journal, erneuter Identitätsprüfung und bytegenauem Restore (AXS-035 bis AXS-040).",
            "Systemdateien werden nie auf einen einzelnen schwachen Hinweis hin entfernt."),
        ["privacy"] = new("Datenschutz", "Lokal · keine Cloud · kein Konto",
            "Diese Vorversion sendet keine Daten: keine Telemetrie, keine Cloud-Abfrage, kein Datei-Upload. Berichte bleiben in deinem Benutzerordner.",
            "Eine optionale Cloud-Reputation kommt erst mit ausdrücklicher Freigabe pro Upload, Zweckangabe und Löschweg (AXS-079, AXS-080).",
            "Auch Hashes und Metadaten sind nicht automatisch anonym. Deshalb ist die Cloud standardmäßig aus."),
        ["settings"] = new("Einstellungen", "Nur Anzeige",
            "", "Einstellbare Policies mit Rollen und Audit folgen mit dem Dienst (AXS-017).",
            "Standardbenutzer können keine globalen Ausnahmen setzen."),
        ["help"] = new("Hilfe", "AXSafe Vorversion 0.1",
            "AXSafe ist ein Open-Development-Projekt für einen ehrlichen, mehrschichtigen Windows-Schutz. Diese Vorversion ist ein Datei-Scanner auf Anforderung.",
            "Installation: axsafe.exe und den Ordner 'rules' in den Unterordner 'cli' neben AXSafe.exe legen. Optional ClamAV installieren. Projekt und Doku: github.com/tkacalex/AXSafe",
            "Kein Antivirus erkennt jede Schadsoftware. Lass Microsoft Defender aktiv."),
    };

    public MainWindow()
    {
        InitializeComponent();
        // An kleine Bildschirme und hohe Skalierung anpassen (125–200 %).
        var area = SystemParameters.WorkArea;
        Width = Math.Min(Width, area.Width);
        Height = Math.Min(Height, area.Height);
        MinWidth = Math.Min(MinWidth, area.Width);
        MinHeight = Math.Min(MinHeight, area.Height);
        Loaded += async (_, _) =>
        {
            await RefreshEnginesAsync();
            await RunCommandLineScanAsync();
        };
        ReportsDirText.Text = $"Ablage: {_cli.ReportsDir}";
    }

    /// <summary>
    /// <c>AXSafe.exe --scan &lt;Pfad&gt; [...]</c> startet direkt einen Scan
    /// (Grundlage für ein späteres Explorer-Kontextmenü, AXS-026).
    /// </summary>
    private async Task RunCommandLineScanAsync()
    {
        var args = Environment.GetCommandLineArgs().Skip(1).ToList();
        var i = args.IndexOf("--scan");
        if (i < 0) return;
        var paths = args.Skip(i + 1).Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToList();
        if (paths.Count == 0) return;
        GoScan_Click(this, new RoutedEventArgs());
        await RunScanAsync(paths);
    }

    private Brush B(string key) => (Brush)FindResource(key);

    private bool _clamavDecided;

    private async void UseClamav_Click(object sender, RoutedEventArgs e)
    {
        _clamavDecided = true;
        await RefreshEnginesAsync();
    }

    private async Task RefreshEnginesAsync()
    {
        // Beim ersten Start prüfen, ob ClamAV überhaupt vorhanden ist. Fehlt es,
        // wird es abgewählt und der kleinere Prüfumfang sichtbar erklärt,
        // statt jeden Scan mit „Fehler“ enden zu lassen.
        if (!_clamavDecided && _cli.Available)
        {
            var probe = await _cli.GetEnginesAsync(true, CancellationToken.None);
            var clamProbe = probe.FirstOrDefault(e => e.Name == "clamav");
            if (clamProbe is not null && clamProbe.Health.State != "ready")
            {
                UseClamav.IsChecked = false;
                ClamavHint.Visibility = Visibility.Visible;
            }
            _clamavDecided = true;
        }
        var engines = _cli.Available
            ? await _cli.GetEnginesAsync(UseClamav.IsChecked == true, CancellationToken.None)
            : new List<EngineInfo>();
        EngineList.ItemsSource = engines;
        EngineEmpty.Visibility = engines.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var yara = engines.FirstOrDefault(e => e.Name == "yara-x");
        var clam = engines.FirstOrDefault(e => e.Name == "clamav");
        string EngState(EngineInfo? e) => e is null
            ? (UseClamav.IsChecked == true ? "nicht gefunden" : "abgewählt")
            : e.Health.State == "ready" ? "bereit" : "Fehler";
        Brush EngBrush(EngineInfo? e) => e?.Health.State == "ready" ? B("Green") : B("Red");

        ModuleList.ItemsSource = new List<ModuleState>
        {
            new("Dateiprüfung auf Anforderung", _cli.Available ? "verfügbar" : "CLI fehlt", _cli.Available ? B("Green") : B("Red")),
            new("Eigene Regeln (YARA-X)", EngState(yara), EngBrush(yara)),
            new("ClamAV-Signaturen", EngState(clam), clam is null ? B("Muted") : EngBrush(clam)),
            new("Echtzeitschutz", "fehlt · P08", B("Amber")),
            new("Skripte & Speicher (AMSI)", "fehlt · P07", B("Amber")),
            new("Ransomware-Schutz", "fehlt · P09", B("Amber")),
            new("Quarantäne", "fehlt · P05", B("Amber")),
            new("Sichere Updates", "fehlt · P04", B("Amber")),
            new("Web & Phishing", "fehlt · P10", B("Amber")),
            new("Anhangprüfung (E-Mail)", "fehlt · P10", B("Amber")),
            new("Selbstschutz", "fehlt · P11", B("Amber")),
            new("Cloud", "aus", B("Muted")),
        };

        // Gesundheit: nie grün, solange kein Echtzeitschutz und kein Dienst existiert.
        if (!_cli.Available || yara?.Health.State != "ready")
        {
            HealthDot.Fill = B("Red");
            HealthText.Text = "Nicht betriebsbereit";
            HealthDetail.Text = !_cli.Available ? "axsafe.exe nicht gefunden" : "Regelsatz nicht geladen";
        }
        else
        {
            HealthDot.Fill = B("Amber");
            HealthText.Text = "Eingeschränkt";
            HealthDetail.Text = "Nur Scan auf Anforderung · Dienst fehlt (P02)";
        }
    }

    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is not RadioButton rb || PageOverview is null) return;
        var tag = rb.Tag as string ?? "overview";
        PageOverview.Visibility = tag == "overview" ? Visibility.Visible : Visibility.Collapsed;
        PageScan.Visibility = tag == "scan" ? Visibility.Visible : Visibility.Collapsed;
        PageReports.Visibility = tag == "reports" ? Visibility.Visible : Visibility.Collapsed;
        PageInfo.Visibility = Pages.ContainsKey(tag) ? Visibility.Visible : Visibility.Collapsed;
        if (Pages.TryGetValue(tag, out var p))
        {
            InfoTitle.Text = p.Title;
            InfoState.Text = p.State;
            InfoNow.Text = tag == "settings"
                ? $"axsafe.exe: {_cli.ExePath ?? "nicht gefunden"}\nBerichte: {_cli.ReportsDir}"
                : p.Now;
            InfoNeeded.Text = p.Needed;
            InfoLimit.Text = p.Limit;
        }
        if (tag == "reports") LoadReports();
    }

    private void GoScan_Click(object sender, RoutedEventArgs e)
    {
        foreach (var child in LogicalTreeHelper.GetChildren((DependencyObject)NavOverview.Parent))
            if (child is RadioButton rb && rb.Tag as string == "scan") rb.IsChecked = true;
    }

    private async void ScanFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Title = "Ordner für die Prüfung wählen", Multiselect = true };
        if (dlg.ShowDialog(this) == true) await RunScanAsync(dlg.FolderNames);
    }

    private async void ScanFiles_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Dateien für die Prüfung wählen", Multiselect = true };
        if (dlg.ShowDialog(this) == true) await RunScanAsync(dlg.FileNames);
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => _scanCts?.Cancel();

    private void SetBusy(bool busy)
    {
        BtnFolder.IsEnabled = !busy;
        BtnFiles.IsEnabled = !busy;
        BtnCancel.IsEnabled = busy;
        ScanProgress.IsIndeterminate = busy;
    }

    private async Task RunScanAsync(IReadOnlyList<string> paths)
    {
        if (!_cli.Available)
        {
            ScanStatus.Text = "axsafe.exe wurde nicht gefunden. Siehe Hilfe.";
            return;
        }
        _scanCts = new CancellationTokenSource();
        SetBusy(true);
        ResultList.ItemsSource = null;
        ScanSummary.Text = "";
        ScanStatus.Text = $"Prüfe {paths.Count} Auswahl(en) …";
        try
        {
            var r = await _cli.ScanAsync(paths, UseClamav.IsChecked == true, _scanCts.Token);
            if (r.Report is null)
            {
                ScanStatus.Text = $"Fehler: {r.Error}";
                return;
            }
            ShowReport(r.Report);
        }
        catch (OperationCanceledException)
        {
            ScanStatus.Text = "Abgebrochen. Es liegt kein vollständiges Ergebnis vor.";
        }
        finally
        {
            SetBusy(false);
            _scanCts = null;
        }
    }

    private void ShowReport(ScanReport rep)
    {
        // Funde und Lücken zuerst, damit nichts in langen Listen untergeht.
        ResultList.ItemsSource = rep.Files
            .OrderBy(f => VerdictText.IsDetection(f.Verdict) ? 0 : f.Verdict == "NoDetection" ? 2 : 1)
            .ToList();
        var s = rep.Summary;
        ScanStatus.Text = VerdictText.IsDetection(rep.Overall)
            ? $"Fund: {VerdictText.Label(rep.Overall)}. AXSafe hat nichts verändert (Vorversion meldet nur)."
            : !rep.Complete
                ? "Unvollständig: Einige Objekte konnten nicht vollständig geprüft werden."
                : "Nichts erkannt – nur im geprüften Umfang, kein Beweis für Harmlosigkeit.";
        ScanSummary.Text = $"{s.Objects} Objekte · {s.Detections} mit Fund · {s.Incomplete} unvollständig · {s.NoDetection} ohne Fund · {s.BytesRead:N0} Bytes · {rep.DurationMs} ms";

        StatLast.Text = DateTime.TryParse(rep.FinishedUtc, out var t) ? t.ToLocalTime().ToString("dd.MM. HH:mm") : "unbekannt";
        StatObjects.Text = s.Objects.ToString("N0");
        StatDetections.Text = s.Detections.ToString("N0");
        StatIncomplete.Text = s.Incomplete.ToString("N0");
    }

    private void LoadReports()
    {
        try
        {
            ReportList.ItemsSource = Directory.Exists(_cli.ReportsDir)
                ? Directory.GetFiles(_cli.ReportsDir, "*.json").OrderDescending().Select(Path.GetFileName).ToList()
                : new List<string?> { "Noch keine Berichte." };
        }
        catch (IOException ex)
        {
            ReportList.ItemsSource = new List<string> { $"Fehler: {ex.Message}" };
        }
    }

    private void RefreshReports_Click(object sender, RoutedEventArgs e) => LoadReports();

    private void OpenReports_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(_cli.ReportsDir);
        Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { _cli.ReportsDir }, UseShellExecute = false });
    }
}
