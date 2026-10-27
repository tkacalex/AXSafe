#![no_main]
// Rahmen des Worker-Protokolls: Längenangaben dürfen nie zu großen
// Allokationen oder Paniken führen.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let mut r = std::io::Cursor::new(data);
    while let Ok(Some((_kind, payload))) = axsafe_workerproto::read_frame(&mut r, 1024 * 1024) {
        axsafe_core::fuzzing::worker_antwort(&payload);
    }
});
