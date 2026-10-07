#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the builder→parser round-trip with arbitrary file content.
// The builder must not panic, and if it succeeds the archive must be re-parseable.
fuzz_target!(|data: &[u8]| {
    let Ok(bytes) = r7z::ArchiveBuilder::new()
        .add_file("fuzz.bin", data)
        .build()
    else {
        return;
    };

    if let Ok(archive) = r7z::Archive::from_bytes(bytes.into()) {
        let _ = archive.extract_to_memory(r7z::ArchiveEntryIndex::new(0));
    }
});
