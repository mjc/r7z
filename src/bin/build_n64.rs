/// Build a .7z archive from all files under `/mnt/emulation/n64` (or a custom root dir).
///
/// Usage: `build_n64` \[root\_dir\] \[output.7z\]
///
/// Defaults:
/// - `root_dir` = `/mnt/emulation/n64`
/// - `output`   = `/tmp/n64_build.7z`
///
/// Files are piped one at a time through the LZMA2 encoder directly to the output file.
/// Neither all input data nor the full compressed archive is held in memory.
use r7z::build_streaming;
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) -> io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<io::Result<_>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, root, out)?;
        } else {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            out.push((rel, path));
        }
    }
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let root: PathBuf = args
        .get(1)
        .map_or_else(|| PathBuf::from("/mnt/emulation/n64"), PathBuf::from);
    let out_path: PathBuf = args
        .get(2)
        .map_or_else(|| PathBuf::from("/tmp/n64_build.7z"), PathBuf::from);

    if !root.exists() {
        eprintln!("Error: root directory {} does not exist", root.display());
        std::process::exit(1);
    }

    eprintln!("Scanning {} ...", root.display());
    let t0 = Instant::now();
    let mut paths: Vec<(String, PathBuf)> = Vec::new();
    walk(&root, &root, &mut paths)?;
    let total_size: u64 = paths
        .iter()
        .filter_map(|(_, p)| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    eprintln!(
        "Found {} files  ({:.2} MiB)  in {} ms",
        paths.len(),
        total_size as f64 / (1024.0 * 1024.0),
        t0.elapsed().as_millis(),
    );

    eprintln!("Building archive -> {} ...", out_path.display());
    let t_build = Instant::now();

    let out_file = BufWriter::new(File::create(&out_path)?);

    let entries = paths.iter().map(|(rel, path)| {
        let f = File::open(path).unwrap_or_else(|e| panic!("cannot open {}: {e}", path.display()));
        (rel.clone(), f)
    });

    build_streaming(entries, out_file)
        .map_err(|e| io::Error::other(format!("build error: {e:?}")))?;

    let out_size = std::fs::metadata(&out_path)?.len();
    let ratio = out_size as f64 / total_size.max(1) as f64 * 100.0;
    eprintln!(
        "Done: {:.2} MiB  ({ratio:.1}% of raw)  in {} ms",
        out_size as f64 / (1024.0 * 1024.0),
        t_build.elapsed().as_millis(),
    );
    Ok(())
}
