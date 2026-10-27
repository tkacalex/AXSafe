//! Testprogramm für AXS-028 („geprüfte Programme werden nie ausgeführt“).
//! Wird es gestartet, legt es sofort `AUSGEFUEHRT-<name>.txt` neben sich
//! und im aktuellen Ordner an. Der Test prüft, dass diese Datei nach einem
//! Scan NICHT existiert. Harmlos; tut sonst nichts.

fn main() {
    let exe = std::env::current_exe().unwrap_or_default();
    let name = exe
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let file = format!("AUSGEFUEHRT-{name}.txt");
    if let Some(d) = exe.parent() {
        let _ = std::fs::write(d.join(&file), b"ausgefuehrt");
    }
    let _ = std::fs::write(&file, b"ausgefuehrt");
}
