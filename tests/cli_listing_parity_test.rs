#![allow(clippy::pedantic)]

mod support;

use std::collections::BTreeSet;
use std::fs;

use support::{create_p7zip_archive, list_with_p7zip, list_with_p7zip_technical, list_with_r7z};
use tempfile::tempdir;

#[derive(Debug, PartialEq, Eq)]
struct NormalizedArchiveListing {
    archive_type: Option<String>,
    method_bases: BTreeSet<String>,
    entries: Vec<NormalizedEntry>,
}

#[derive(Debug, PartialEq, Eq)]
struct NormalizedEntry {
    path: String,
    size: Option<u64>,
    kind: EntryKind,
    method_bases: BTreeSet<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum EntryKind {
    File,
    Directory,
    Unknown,
}

#[test]
fn technical_listing_normalizes_paths_sizes_and_methods_against_p7zip() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(input.join("nested/empty_dir")).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("nested/b.txt"), b"bravo").unwrap();
    let archive = tmp.path().join("listing.7z");

    create_p7zip_archive(
        &input,
        &archive,
        &["a.txt", "nested"],
        &["-m0=LZMA2", "-mmt=off"],
    );

    let p7zip_output = list_with_p7zip_technical(tmp.path(), &archive);
    let r7z_output = list_with_r7z(&["l", "-slt", archive.to_str().unwrap()], tmp.path());

    assert_eq!(
        stable_listing_body(&r7z_output),
        stable_listing_body(&p7zip_output)
    );

    let p7zip = parse_technical_listing(&p7zip_output);
    let r7z = parse_technical_listing(&r7z_output);

    assert_eq!(r7z, p7zip);
}

#[test]
fn human_listing_normalizes_paths_sizes_and_kinds_against_p7zip() {
    let tmp = tempdir().unwrap();
    let input = tmp.path().join("input");
    fs::create_dir_all(input.join("nested/empty_dir")).unwrap();
    fs::write(input.join("a.txt"), b"alpha").unwrap();
    fs::write(input.join("nested/b.txt"), b"bravo").unwrap();
    let archive = tmp.path().join("human-listing.7z");

    create_p7zip_archive(
        &input,
        &archive,
        &["a.txt", "nested"],
        &["-m0=LZMA2", "-mmt=off"],
    );

    let p7zip_output = list_with_p7zip(tmp.path(), &archive);
    let r7z_output = list_with_r7z(&["l", archive.to_str().unwrap()], tmp.path());

    assert_eq!(
        stable_listing_body(&r7z_output),
        stable_listing_body(&p7zip_output)
    );

    let p7zip = parse_human_listing(&p7zip_output);
    let r7z = parse_human_listing(&r7z_output);

    assert_eq!(r7z, p7zip);
}

#[test]
fn p7zip_created_listing_bodies_match_for_supported_method_matrix() {
    for case in [
        ListingCase {
            name: "lzma2-nonsolid",
            switches: &["-m0=LZMA2", "-ms=off", "-mmt=off"],
        },
        ListingCase {
            name: "ppmd",
            switches: &["-m0=PPMd", "-mmt=off"],
        },
        ListingCase {
            name: "aes-content",
            switches: &["-m0=LZMA2", "-psecret", "-mmt=off"],
        },
    ] {
        let tmp = tempdir().unwrap();
        let input = tmp.path().join("input");
        write_listing_fixture(&input);
        let archive = tmp.path().join(format!("{}.7z", case.name));

        create_p7zip_archive(&input, &archive, &["alpha.txt", "nested"], case.switches);

        assert_listing_bodies_match_p7zip(tmp.path(), &archive);
    }
}

#[test]
fn r7z_created_listing_bodies_match_p7zip_for_metadata_light_archives() {
    for case in [
        R7zListingCase {
            name: "lzma2",
            codec: r7z::Codec::Lzma2,
            encryption: false,
        },
        R7zListingCase {
            name: "ppmd",
            codec: r7z::Codec::Ppmd,
            encryption: false,
        },
        R7zListingCase {
            name: "aes-content",
            codec: r7z::Codec::Lzma2,
            encryption: true,
        },
    ] {
        let tmp = tempdir().unwrap();
        let archive = tmp.path().join(format!("r7z-{}.7z", case.name));
        let mut options = r7z::ArchiveOptions {
            codec: case.codec,
            ..Default::default()
        };
        if case.encryption {
            options.encryption = Some(r7z::EncryptionOptions::default_for_password("secret"));
        }
        let bytes = r7z::ArchiveBuilder::new()
            .options(options)
            .add_file("alpha.txt", b"alpha")
            .add_file("nested/bravo.txt", b"bravo")
            .build()
            .unwrap();
        fs::write(&archive, bytes).unwrap();

        assert_listing_bodies_match_p7zip(tmp.path(), &archive);
    }
}

struct ListingCase {
    name: &'static str,
    switches: &'static [&'static str],
}

struct R7zListingCase {
    name: &'static str,
    codec: r7z::Codec,
    encryption: bool,
}

fn write_listing_fixture(input: &std::path::Path) {
    fs::create_dir_all(input.join("nested/empty_dir")).unwrap();
    fs::write(input.join("alpha.txt"), b"alpha").unwrap();
    fs::write(input.join("nested/bravo.txt"), b"bravo").unwrap();
}

fn assert_listing_bodies_match_p7zip(dir: &std::path::Path, archive: &std::path::Path) {
    let p7zip_human = list_with_p7zip(dir, archive);
    let r7z_human = list_with_r7z(&["l", archive.to_str().unwrap()], dir);
    assert_eq!(
        stable_listing_body(&r7z_human),
        stable_listing_body(&p7zip_human),
        "human listing body mismatch for {}",
        archive.display()
    );

    let p7zip_technical = list_with_p7zip_technical(dir, archive);
    let r7z_technical = list_with_r7z(&["l", "-slt", archive.to_str().unwrap()], dir);
    assert_eq!(
        stable_listing_body(&r7z_technical),
        stable_listing_body(&p7zip_technical),
        "technical listing body mismatch for {}",
        archive.display()
    );
}

fn stable_listing_body(text: &str) -> &str {
    let mut offset = 0usize;
    for line in text.split_inclusive('\n') {
        if line.trim_end_matches(['\r', '\n']).starts_with("Path = ") {
            return text[offset..].trim_end_matches(['\r', '\n']);
        }
        offset += line.len();
    }
    text.trim_end_matches(['\r', '\n'])
}

fn parse_technical_listing(text: &str) -> NormalizedArchiveListing {
    let mut listing = NormalizedArchiveListing {
        archive_type: None,
        method_bases: BTreeSet::new(),
        entries: Vec::new(),
    };
    let mut current: Option<NormalizedEntry> = None;
    let mut after_separator = false;
    let mut saw_separator = false;

    for line in text.lines() {
        if line == "----------" {
            saw_separator = true;
            after_separator = true;
            continue;
        }
        if line.is_empty() {
            if let Some(entry) = current.take() {
                listing.entries.push(entry);
            }
            continue;
        }
        if saw_separator && !after_separator {
            continue;
        }
        if let Some(value) = line.strip_prefix("Type = ") {
            listing.archive_type = Some(value.to_string());
            continue;
        }
        if let Some(value) = line.strip_prefix("Method = ") {
            let bases = method_bases(value);
            if let Some(entry) = current.as_mut() {
                entry.method_bases = bases;
            } else {
                listing.method_bases = bases;
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("Path = ") {
            if saw_separator || !value.ends_with(".7z") {
                if let Some(entry) = current.take() {
                    listing.entries.push(entry);
                }
                current = Some(NormalizedEntry {
                    path: value.to_string(),
                    size: None,
                    kind: EntryKind::Unknown,
                    method_bases: BTreeSet::new(),
                });
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("Size = ") {
            if let Some(entry) = current.as_mut() {
                entry.size = value.parse::<u64>().ok();
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("Attributes = ") {
            if let Some(entry) = current.as_mut() {
                entry.kind = if value.starts_with('D') {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("Folder = ") {
            if let Some(entry) = current.as_mut() {
                entry.kind = if value == "Directory" {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };
            }
        }
    }
    if let Some(entry) = current {
        listing.entries.push(entry);
    }
    listing
        .entries
        .sort_by(|left, right| left.path.cmp(&right.path));
    listing
}

fn parse_human_listing(text: &str) -> Vec<NormalizedEntry> {
    let mut entries = Vec::new();
    let mut in_rows = false;
    for line in text.lines() {
        if line.starts_with("------------------- -----") {
            in_rows = !in_rows;
            continue;
        }
        if !in_rows || line.trim().is_empty() {
            continue;
        }
        let Some((prefix, name)) = line.rsplit_once("  ") else {
            continue;
        };
        let columns = prefix.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 2 {
            continue;
        }
        let (attr, size) = if columns.len() >= 4 {
            (columns[2], columns[3].parse::<u64>().ok())
        } else {
            (columns[0], columns[1].parse::<u64>().ok())
        };
        entries.push(NormalizedEntry {
            path: name.to_string(),
            size,
            kind: if attr.starts_with('D') {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            method_bases: BTreeSet::new(),
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn method_bases(text: &str) -> BTreeSet<String> {
    text.split_whitespace()
        .map(|method| method.split_once(':').map_or(method, |(base, _)| base))
        .filter(|method| !method.is_empty())
        .map(ToString::to_string)
        .collect()
}
