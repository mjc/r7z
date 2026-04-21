#![allow(dead_code)]
use std::{
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

pub fn write_fixture_tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let files = vec![
        (
            PathBuf::from("alpha.txt"),
            b"alpha payload repeated repeated repeated".to_vec(),
        ),
        (
            PathBuf::from("nested/beta.bin"),
            (0u8..=127).cycle().take(4096).collect(),
        ),
        (
            PathBuf::from("nested/deep/gamma.txt"),
            b"gamma\nwith\nmultiple\nlines\n".to_vec(),
        ),
    ];

    for (name, data) in &files {
        if let Some(parent) = name.parent() {
            fs::create_dir_all(dir.join(parent)).unwrap();
        }
        fs::write(dir.join(name), data).unwrap();
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
