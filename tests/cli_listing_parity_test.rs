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

    let p7zip = parse_technical_listing(&list_with_p7zip_technical(tmp.path(), &archive));
    let r7z = parse_technical_listing(&list_with_r7z(
        &["l", "-slt", archive.to_str().unwrap()],
        tmp.path(),
    ));

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

    let p7zip = parse_human_listing(&list_with_p7zip(tmp.path(), &archive));
    let r7z = parse_human_listing(&list_with_r7z(
        &["l", archive.to_str().unwrap()],
        tmp.path(),
    ));

    assert_eq!(r7z, p7zip);
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
