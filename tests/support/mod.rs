#![allow(clippy::pedantic)]
#![allow(dead_code)]
use std::{
    collections::BTreeSet,
    env,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};

pub fn valid_7z_string() -> Vec<u8> {
    let path = env::current_dir().unwrap().join("tests/fixtures/test_1.7z");
    let mut file = File::open(path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}

/// Run 7z directly, falling back to `nix-shell -p p7zip` if not in PATH.
pub fn run_7z(args: &[&str], dir: &std::path::Path) -> std::process::Output {
    if let Ok(out) = Command::new("7z").args(args).current_dir(dir).output() {
        return out;
    }
    let mut nix_args = vec!["-p", "p7zip", "--run"];
    let quoted: Vec<String> = args.iter().map(|arg| shell_quote(arg)).collect();
    let cmd = format!("7z {}", quoted.join(" "));
    nix_args.push(&cmd);
    Command::new("nix-shell")
        .args(&nix_args)
        .current_dir(dir)
        .output()
        .expect("nix-shell not available; install p7zip or enter a nix shell with p7zip")
}

pub fn run_7z_checked(args: &[&str], dir: &Path) -> std::process::Output {
    let out = run_7z(args, dir);
    assert!(
        out.status.success(),
        "7z failed in {} with args {:?}\nstdout:\n{}\nstderr:\n{}",
        dir.display(),
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

pub fn write_fixture_tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let files = fixture_files();
    fs::create_dir_all(root.join("nested dir/empty_dir")).unwrap();
    fs::create_dir_all(root.join("deep/path")).unwrap();

    for (path, data) in &files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, data).unwrap();
    }

    files
}

pub fn write_fixture_files(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let files = fixture_files();
    for (path, data) in &files {
        let full = root.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(full, data).unwrap();
    }
    files
}

pub fn assert_extracted_files(root: &Path, expected: &[(PathBuf, Vec<u8>)]) {
    for (name, original) in expected {
        let path = root.join(name);
        assert!(
            path.is_file(),
            "expected extracted file missing: {}",
            path.display()
        );
        let extracted = fs::read(&path).unwrap();
        assert_eq!(
            extracted,
            *original,
            "extracted bytes differ for {}",
            name.display()
        );
    }
}

pub fn create_p7zip_archive(dir: &Path, archive_path: &Path, files: &[&str], args: &[&str]) {
    let mut argv: Vec<&str> = vec!["a", archive_path.to_str().unwrap()];
    argv.extend_from_slice(files);
    argv.extend_from_slice(args);
    let out = run_7z(&argv, dir);
    assert!(
        out.status.success(),
        "7z a failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

pub fn extract_with_p7zip(dir: &Path, archive_path: &Path, out_dir: &Path) {
    fs::create_dir_all(out_dir).unwrap();
    let out_arg = format!("-o{}", out_dir.to_str().unwrap());
    let out = run_7z(&["x", "-y", archive_path.to_str().unwrap(), &out_arg], dir);
    assert!(
        out.status.success(),
        "7z x failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

pub fn extract_with_r7z(archive: &Path, out_dir: &Path) {
    fs::create_dir_all(out_dir).unwrap();
    let archive = r7z::Archive::open(archive).unwrap();
    archive.extract_all(out_dir).unwrap();
}

pub fn list_with_p7zip(dir: &Path, archive_path: &Path) -> String {
    let out = run_7z(&["l", archive_path.to_str().unwrap()], dir);
    assert!(
        out.status.success(),
        "7z l failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn list_with_p7zip_technical(dir: &Path, archive_path: &Path) -> String {
    let out = run_7z(&["l", "-slt", archive_path.to_str().unwrap()], dir);
    assert!(
        out.status.success(),
        "7z l -slt failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn list_with_r7z(args: &[&str], dir: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_r7z"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("r7z binary should run");
    assert!(
        out.status.success(),
        "r7z list failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn assert_trees_equal(expected: &Path, actual: &Path) {
    let expected_entries = tree_entries(expected);
    let actual_entries = tree_entries(actual);
    assert_eq!(actual_entries, expected_entries, "tree entry mismatch");

    for entry in expected_entries {
        let expected_path = expected.join(&entry);
        let actual_path = actual.join(&entry);
        assert_eq!(
            actual_path.is_dir(),
            expected_path.is_dir(),
            "directory type mismatch for {}",
            entry.display()
        );
        assert_eq!(
            actual_path.is_file(),
            expected_path.is_file(),
            "file type mismatch for {}",
            entry.display()
        );
        if expected_path.is_file() {
            assert_eq!(
                fs::read(&actual_path).unwrap(),
                fs::read(&expected_path).unwrap(),
                "file content mismatch for {}",
                entry.display()
            );
        }
    }
}

fn shell_quote(arg: &str) -> String {
    if arg
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_./:=+".contains(&b))
    {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

fn fixture_files() -> Vec<(PathBuf, Vec<u8>)> {
    let mut binary = Vec::with_capacity(1024 * 1024);
    for i in 0..1024 * 1024 {
        binary.push(((i * 31 + i / 7) & 0xff) as u8);
    }

    let mut code = vec![0x90u8; 16 * 1024];
    for &pos in &[8usize, 64, 255, 1024, 4096, 8191, 12000, 15000] {
        code[pos] = if pos % 2 == 0 { 0xE8 } else { 0xE9 };
        code[pos + 1] = (pos * 3) as u8;
        code[pos + 2] = ((pos * 3) >> 8) as u8;
        code[pos + 3] = 0;
        code[pos + 4] = 0;
    }

    vec![
        (PathBuf::from("alpha.txt"), b"alpha text\n".to_vec()),
        (
            PathBuf::from("nested dir/beta.txt"),
            b"beta text with spaces in the path\n".to_vec(),
        ),
        (
            PathBuf::from("nested dir/unicode-\u{2603}.txt"),
            "snowman payload\n".as_bytes().to_vec(),
        ),
        (PathBuf::from("deep/path/empty.txt"), Vec::new()),
        (PathBuf::from("binary/payload.bin"), binary),
        (PathBuf::from("bin/code.bin"), code),
    ]
}

fn tree_entries(root: &Path) -> BTreeSet<PathBuf> {
    walkdir::WalkDir::new(root)
        .min_depth(1)
        .into_iter()
        .map(|entry| entry.unwrap())
        .map(|entry| entry.path().strip_prefix(root).unwrap().to_path_buf())
        .collect()
}
