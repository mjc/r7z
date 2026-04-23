use r7z::{
    Archive, ArchiveBuilder, ArchiveOptions, Codec, EncryptionOptions, ListingEntryKind, SolidMode,
};

fn open_listing(bytes: Vec<u8>) -> r7z::ArchiveListing {
    let physical_size = bytes.len() as u64;
    Archive::from_bytes(bytes.into())
        .unwrap()
        .listing(Some(physical_size))
        .unwrap()
}

#[test]
fn listing_metadata_single_file_uses_header_sizes_without_extraction() {
    let bytes = ArchiveBuilder::new()
        .compression(Codec::Lzma2)
        .add_file("payload.txt", b"hello listing metadata")
        .build()
        .unwrap();

    let listing = open_listing(bytes);

    assert_eq!(listing.archive_type, "7z");
    assert_eq!(listing.blocks, 1);
    assert!(!listing.solid);
    assert_eq!(listing.methods, vec!["LZMA2"]);
    assert_eq!(listing.entries.len(), 1);
    let entry = &listing.entries[0];
    assert_eq!(entry.path, "payload.txt");
    assert_eq!(entry.kind, ListingEntryKind::File);
    assert_eq!(entry.size, Some(22));
    assert!(entry.packed_size.is_some());
    assert_eq!(entry.block, Some(0));
    assert_eq!(entry.methods, vec!["LZMA2"]);
    assert!(!entry.encrypted);
    assert!(listing.headers_size.is_some());
}

#[test]
fn listing_metadata_marks_only_first_solid_entry_with_packed_size() {
    let bytes = ArchiveBuilder::new()
        .add_file("a.txt", b"alpha")
        .add_file("b.txt", b"bravo")
        .build()
        .unwrap();

    let listing = open_listing(bytes);

    assert_eq!(listing.blocks, 1);
    assert!(listing.solid);
    assert_eq!(listing.entries[0].block, Some(0));
    assert_eq!(listing.entries[1].block, Some(0));
    assert!(listing.entries[0].packed_size.is_some());
    assert_eq!(listing.entries[1].packed_size, None);
}

#[test]
fn listing_metadata_tracks_non_solid_blocks() {
    let bytes = ArchiveBuilder::new()
        .options(ArchiveOptions {
            compression: r7z::CompressionOptions {
                solid: SolidMode::NonSolid,
                ..Default::default()
            },
            ..Default::default()
        })
        .add_file("a.txt", b"alpha")
        .add_file("b.txt", b"bravo")
        .build()
        .unwrap();

    let listing = open_listing(bytes);

    assert_eq!(listing.blocks, 2);
    assert!(!listing.solid);
    assert_eq!(listing.entries[0].block, Some(0));
    assert_eq!(listing.entries[1].block, Some(1));
    assert!(listing.entries[0].packed_size.is_some());
    assert!(listing.entries[1].packed_size.is_some());
}

#[test]
fn listing_metadata_handles_directory_and_empty_file_without_blocks() {
    let bytes = ArchiveBuilder::new()
        .add_directory("dir", r7z::EntryMeta::default())
        .add_empty_file("dir/empty.txt", r7z::EntryMeta::default())
        .build()
        .unwrap();

    let listing = open_listing(bytes);

    assert_eq!(listing.blocks, 0);
    assert_eq!(listing.entries[0].kind, ListingEntryKind::Directory);
    assert_eq!(listing.entries[0].size, Some(0));
    assert_eq!(listing.entries[0].block, None);
    assert_eq!(listing.entries[1].kind, ListingEntryKind::File);
    assert_eq!(listing.entries[1].size, Some(0));
    assert_eq!(listing.entries[1].block, None);
    assert_eq!(listing.entries[1].crc, Some(0));
}

#[test]
fn listing_metadata_marks_encrypted_content_entries() {
    let bytes = ArchiveBuilder::new()
        .options(ArchiveOptions {
            encryption: Some(EncryptionOptions::default_for_password("secret")),
            ..Default::default()
        })
        .add_file("secret.txt", b"classified")
        .build()
        .unwrap();

    let listing = open_listing(bytes);

    assert_eq!(listing.blocks, 1);
    assert!(listing.methods.contains(&"7zAES".to_string()));
    assert_eq!(listing.entries[0].path, "secret.txt");
    assert!(listing.entries[0].encrypted);
    assert!(listing.entries[0].methods.contains(&"7zAES".to_string()));
}
