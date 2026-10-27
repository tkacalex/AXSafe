#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    axsafe_core::fuzzing::typ_und_merkmale(data);
});
