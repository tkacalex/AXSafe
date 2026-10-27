#![no_main]
use std::sync::OnceLock;

static DIR: OnceLock<std::path::PathBuf> = OnceLock::new();

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let dir = DIR.get_or_init(|| {
        let d = std::env::temp_dir().join(format!("axsafe-fuzz-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    });
    axsafe_core::fuzzing::fortsetzung_und_cache(data, dir);
});
