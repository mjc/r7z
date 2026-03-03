/// Build a .7z archive from all files under /mnt/emulation/n64 (or a custom root dir).
///
/// Usage: build_n64 [root_dir] [output.7z]
///
/// Defaults to:
///   root_dir  = /mnt/emulation/n64
///   output    = /tmp/n64_build.7z
///
/// Run under flamegraph with:
///   cargo flamegraph --bin build_n64 -- /mnt/emulation/n64 /tmp/n64_build.7z
use r7z::{ArchiveBuilder, Codec};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn walk(dir: &Path, root: &Path, files: &mut Vec<(String, Vec<u8>)>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk(&path, root, files)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            let data = std::fs::read(&path)?;
            eprintln!("  [{:>8} bytes] {rel}", data.len());
            files.push((rel, data));
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let root: PathBuf = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/mnt/emulation/n64"));
    let out: PathBuf = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/n64_build.7z"));

    if !root.exists() {
        eprintln!("Error: root directory {} does not exist", root.display());
        std::process::exit(1);
    }

    eprintln!("Scanning {}  ...", root.display());
    let t_scan = Instant::now();
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    walk(&root, &root, &mut files)?;
    let scan_ms = t_scan.elapsed().as_millis();

    let total_raw: usize = files.iter().map(|(_, d)| d.len()).sum();
    eprintln!(
        "Scanned {} files  ({:.2} MiB)  in {scan_ms} ms",
        files.len(),
        total_raw as f64 / (1024.0 * 1024.0),
    );

    eprintln!("Building archive with LZMA2 ...");
    let t_build = Instant::now();
    let mut builder = ArchiveBuilder::new().compression(Codec::Lzma2);
    for (name, data) in &files {
        builder = builder.add_file(name, data);
    }
    let archive = builder.build().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("build error: {e:?}"))
    })?;
    let build_ms = t_build.elapsed().as_millis();

    let ratio = archive.len() as f64 / total_raw.max(1) as f64 * 100.0;
    eprintln!(
        "Built {:.2} MiB  ({ratio:.1}% of raw)  in {build_ms} ms",
        archive.len() as f64 / (1024.0 * 1024.0),
    );

    std::fs::write(&out, &archive)?;
    eprintln!("Written to {}", out.display());
    Ok(())
}
