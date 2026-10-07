#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz full archive parsing and extraction: any input must not panic.
fuzz_target!(|data: &[u8]| {
    if let Ok(archive) = r7z::Archive::from_bytes(data.to_vec().into()) {
        for entry in archive.entries() {
            let _ = archive.extract_to_memory(entry.index);
        }
    }
});
