#![allow(clippy::pedantic)]

use std::{fs, path::Path};

#[derive(Debug)]
struct CorpusCase {
    path: String,
    password: Option<String>,
    expectation: Expectation,
    expected_files: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum Expectation {
    Extract,
    OpenOnly,
}

#[test]
fn checked_in_7z_corpus_cases_open_and_extract_as_expected() {
    for case in read_manifest("tests/corpus/7z/manifest.tsv") {
        let path = Path::new(&case.path);
        assert!(
            path.is_file(),
            "corpus archive is missing: {}",
            path.display()
        );
        let archive = r7z::Archive::open_with_password(path, case.password.as_deref())
            .unwrap_or_else(|err| {
                panic!("failed to open corpus archive {}: {err}", path.display())
            });

        assert_eq!(
            archive.num_files(),
            case.expected_files,
            "unexpected file count for {}",
            path.display()
        );
        if case.expectation == Expectation::Extract {
            extract_all_file_entries(&archive, case.password.as_deref(), path);
        }
    }
}

fn extract_all_file_entries(archive: &r7z::Archive, password: Option<&str>, path: &Path) {
    let Some(files) = archive.files_info() else {
        return;
    };
    for idx in 0..archive.num_files() {
        if files.is_directory(idx) || files.is_anti(idx) {
            continue;
        }
        archive
            .extract_to_memory_with_password(idx, password)
            .unwrap_or_else(|err| {
                panic!(
                    "failed to extract corpus entry {} from {}: {err}",
                    files.name(idx).unwrap_or_else(|| format!("entry-{idx}")),
                    path.display()
                )
            });
    }
}

fn read_manifest(path: &str) -> Vec<CorpusCase> {
    let text =
        fs::read_to_string(path).unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    let cases = text
        .lines()
        .enumerate()
        .filter_map(|(line_idx, line)| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            Some(parse_manifest_line(line_idx + 1, line))
        })
        .collect::<Vec<_>>();
    assert!(
        !cases.is_empty(),
        "{path} must list at least one corpus case"
    );
    cases
}

fn parse_manifest_line(line_idx: usize, line: &str) -> CorpusCase {
    let fields = line.split('\t').collect::<Vec<_>>();
    assert_eq!(
        fields.len(),
        4,
        "corpus manifest line {line_idx} must have 4 tab-separated fields"
    );
    CorpusCase {
        path: fields[0].to_string(),
        password: match fields[1] {
            "-" => None,
            password => Some(password.to_string()),
        },
        expectation: match fields[2] {
            "extract" => Expectation::Extract,
            "open" => Expectation::OpenOnly,
            other => panic!("unknown corpus expectation {other:?} on line {line_idx}"),
        },
        expected_files: fields[3]
            .parse()
            .unwrap_or_else(|err| panic!("invalid file count on line {line_idx}: {err}")),
    }
}
