#![allow(dead_code)]
use std::{env, fs::File, io::Read, process::Command};

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
