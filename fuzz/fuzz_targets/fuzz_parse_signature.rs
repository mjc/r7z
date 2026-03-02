#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the SignatureHeader parser: any input must not panic.
fuzz_target!(|data: &[u8]| {
    let _ = r7z::SignatureHeader::parse(data);
});
