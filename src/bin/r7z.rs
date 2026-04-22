use r7z::{
    method_from_id, method_from_name, Archive, ArchiveBuilder, ArchiveEntry, ArchiveOptions, Codec,
    CompressionLevel, EncryptionOptions, EntryMeta, HeaderMode, R7zError, SevenZMethod, SolidMode,
};
use std::{
    collections::BTreeSet,
    env,
    ffi::OsStr,
    fs, io,
    path::{Component, Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const EXIT_OK: u8 = 0;
const EXIT_WARNING: u8 = 1;
const EXIT_FATAL: u8 = 2;
const EXIT_COMMAND_LINE: u8 = 7;

fn main() -> ExitCode {
    match run(env::args().skip(1).collect()) {
        Ok(code) => ExitCode::from(code),
        Err(CliError::Usage(msg)) => {
            eprintln!("Command Line Error: {msg}");
            ExitCode::from(EXIT_COMMAND_LINE)
        }
        Err(CliError::Fatal(err)) => {
            eprintln!("Error: {err}");
            ExitCode::from(EXIT_FATAL)
        }
    }
}

fn run(args: Vec<String>) -> Result<u8, CliError> {
    let cli = Cli::parse(args)?;
    match cli.command {
        Command::List => {
            list_archive(&cli)?;
            Ok(EXIT_OK)
        }
        Command::Test => test_archive(&cli),
        Command::ExtractFull => {
            extract_archive(&cli, false)?;
            Ok(EXIT_OK)
        }
        Command::ExtractFlat => {
            extract_archive(&cli, true)?;
            Ok(EXIT_OK)
        }
        Command::Add => {
            create_archive(&cli, true)?;
            Ok(EXIT_OK)
        }
        Command::Update => {
            update_archive(&cli)?;
            Ok(EXIT_OK)
        }
        Command::Delete => {
            delete_from_archive(&cli)?;
            Ok(EXIT_OK)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    List,
    Test,
    ExtractFull,
    ExtractFlat,
    Add,
    Update,
    Delete,
}

#[derive(Debug)]
struct Cli {
    command: Command,
    archive: PathBuf,
    operands: Vec<PathBuf>,
    output_dir: PathBuf,
    password: Option<String>,
    options: ArchiveOptions,
    technical: bool,
    volume_sizes: Vec<u64>,
}

impl Cli {
    fn parse(mut args: Vec<String>) -> Result<Self, CliError> {
        if args.is_empty() || is_help(&args[0]) {
            return Err(CliError::Usage(usage()));
        }

        let command = match args.remove(0).as_str() {
            "l" => Command::List,
            "t" => Command::Test,
            "x" => Command::ExtractFull,
            "e" => Command::ExtractFlat,
            "a" => Command::Add,
            "u" => Command::Update,
            "d" => Command::Delete,
            other => return Err(CliError::Usage(format!("unsupported command: {other}"))),
        };

        let mut output_dir = PathBuf::from(".");
        let mut password = None;
        let mut options = ArchiveOptions::default();
        let mut technical = false;
        let mut method_was_explicit = false;
        let mut volume_sizes = Vec::new();
        let mut positional = Vec::new();

        for arg in args {
            if let Some(switch) = arg.strip_prefix('-') {
                if switch.is_empty() {
                    positional.push(PathBuf::from(arg));
                    continue;
                }
                parse_switch(
                    switch,
                    &mut output_dir,
                    &mut password,
                    &mut options,
                    &mut technical,
                    &mut method_was_explicit,
                    &mut volume_sizes,
                )?;
            } else {
                positional.push(PathBuf::from(arg));
            }
        }

        let Some(archive) = positional.first().cloned() else {
            return Err(CliError::Usage("archive path is required".to_string()));
        };
        let operands = positional.into_iter().skip(1).collect();

        if let Some(password) = &password {
            let mut encryption = EncryptionOptions::default_for_password(password.clone());
            encryption.encrypt_header = options
                .encryption
                .as_ref()
                .is_some_and(|enc| enc.encrypt_header);
            options.encryption = Some(encryption);
        } else if let Some(encryption) = &options.encryption {
            if encryption.encrypt_header {
                return Err(CliError::Usage("-mhe=on requires -pPASS".to_string()));
            }
            options.encryption = None;
        }

        if !method_was_explicit && options.compression.level == CompressionLevel::Store {
            options.codec = Codec::Copy;
        }

        Ok(Self {
            command,
            archive,
            operands,
            output_dir,
            password,
            options,
            technical,
            volume_sizes,
        })
    }
}

fn parse_switch(
    switch: &str,
    output_dir: &mut PathBuf,
    password: &mut Option<String>,
    options: &mut ArchiveOptions,
    technical: &mut bool,
    method_was_explicit: &mut bool,
    volume_sizes: &mut Vec<u64>,
) -> Result<(), CliError> {
    let lower = switch.to_ascii_lowercase();
    if lower == "slt" {
        *technical = true;
        return Ok(());
    }
    if lower == "y" {
        return Ok(());
    }
    if let Some(dir) = switch.strip_prefix('o') {
        if dir.is_empty() {
            return Err(CliError::Usage(
                "-o requires an attached directory".to_string(),
            ));
        }
        *output_dir = PathBuf::from(dir);
        return Ok(());
    }
    if let Some(pass) = switch.strip_prefix('p') {
        *password = Some(pass.to_string());
        return Ok(());
    }
    if lower.starts_with("m0=") {
        let method = &switch[3..];
        options.codec = codec_from_method_name(method)?;
        *method_was_explicit = true;
        return Ok(());
    }
    if lower.starts_with("mx") {
        options.compression.level = parse_level(switch)?;
        return Ok(());
    }
    if lower.starts_with("ms") {
        options.compression.solid = parse_solid(switch)?;
        return Ok(());
    }
    if lower.starts_with("mf") {
        parse_filter(switch, options)?;
        return Ok(());
    }
    if lower.starts_with("mhe") {
        let enabled = parse_on_off_value(switch, "mhe")?;
        let mut encryption = options
            .encryption
            .take()
            .unwrap_or_else(|| EncryptionOptions::default_for_password(""));
        encryption.encrypt_header = enabled;
        options.header_mode = if enabled {
            HeaderMode::Encoded
        } else {
            options.header_mode
        };
        options.encryption = Some(encryption);
        return Ok(());
    }
    if let Some(size) = switch.strip_prefix('v') {
        volume_sizes.push(parse_size(size)?);
        return Ok(());
    }
    Err(CliError::Usage(format!("unsupported switch: -{switch}")))
}

fn codec_from_method_name(name: &str) -> Result<Codec, CliError> {
    let method =
        method_from_name(name).ok_or_else(|| CliError::Usage(format!("unknown method: {name}")))?;
    match method {
        SevenZMethod::Copy => Ok(Codec::Copy),
        SevenZMethod::Lzma => Ok(Codec::Lzma),
        SevenZMethod::Lzma2 | SevenZMethod::FastLzma2 => Ok(Codec::Lzma2),
        other => Err(CliError::Usage(format!(
            "method {} is tracked for parity but not yet supported by r7z",
            other.name()
        ))),
    }
}

fn parse_filter(switch: &str, options: &mut ArchiveOptions) -> Result<(), CliError> {
    let Some((_, value)) = switch.split_once('=') else {
        return Ok(());
    };
    let method = method_from_name(value)
        .ok_or_else(|| CliError::Usage(format!("unknown filter: {value}")))?;
    match method {
        SevenZMethod::Bcj => {
            if matches!(options.codec, Codec::Lzma2) {
                options.codec = Codec::Lzma2Bcj;
            }
            Ok(())
        }
        other => Err(CliError::Usage(format!(
            "filter {} is tracked for parity but not yet supported by r7z",
            other.name()
        ))),
    }
}

fn parse_level(switch: &str) -> Result<CompressionLevel, CliError> {
    let value = switch
        .split_once('=')
        .map_or_else(|| switch.trim_start_matches("mx"), |(_, value)| value);
    match value {
        "" | "5" => Ok(CompressionLevel::Normal),
        "0" => Ok(CompressionLevel::Store),
        "1" => Ok(CompressionLevel::Fastest),
        "3" => Ok(CompressionLevel::Fast),
        "7" => Ok(CompressionLevel::Maximum),
        "9" => Ok(CompressionLevel::Ultra),
        _ => Err(CliError::Usage(format!(
            "unsupported compression level: {value}"
        ))),
    }
}

fn parse_solid(switch: &str) -> Result<SolidMode, CliError> {
    if !switch.contains('=') {
        return Ok(SolidMode::Solid);
    }
    if parse_on_off_value(switch, "ms")? {
        Ok(SolidMode::Solid)
    } else {
        Ok(SolidMode::NonSolid)
    }
}

fn parse_on_off_value(switch: &str, name: &str) -> Result<bool, CliError> {
    let Some((_, value)) = switch.split_once('=') else {
        return Ok(true);
    };
    match value.to_ascii_lowercase().as_str() {
        "on" | "1" | "yes" => Ok(true),
        "off" | "0" | "no" => Ok(false),
        _ => Err(CliError::Usage(format!("-{name} expects on or off"))),
    }
}

fn parse_size(text: &str) -> Result<u64, CliError> {
    if text.is_empty() {
        return Err(CliError::Usage("-v requires an attached size".to_string()));
    }
    let (digits, multiplier) = match text.as_bytes().last().copied() {
        Some(b'k' | b'K') => (&text[..text.len() - 1], 1024u64),
        Some(b'm' | b'M') => (&text[..text.len() - 1], 1024u64 * 1024),
        Some(b'g' | b'G') => (&text[..text.len() - 1], 1024u64 * 1024 * 1024),
        _ => (text, 1),
    };
    let value = digits
        .parse::<u64>()
        .map_err(|_| CliError::Usage(format!("invalid volume size: {text}")))?;
    value
        .checked_mul(multiplier)
        .filter(|&value| value > 0)
        .ok_or_else(|| CliError::Usage(format!("invalid volume size: {text}")))
}

fn list_archive(cli: &Cli) -> Result<(), CliError> {
    let archive = open_archive(cli)?;
    let selected = selected_patterns(&cli.operands);
    if cli.technical {
        print_technical_listing(&archive, &selected)?;
    } else {
        print_listing(&archive, &cli.archive, &selected)?;
    }
    Ok(())
}

fn print_listing(
    archive: &Archive,
    archive_path: &Path,
    selected: &[String],
) -> Result<(), CliError> {
    println!();
    println!("Path = {}", archive_path.display());
    println!("Type = 7z");
    if let Ok(meta) = fs::metadata(archive_path) {
        println!("Physical Size = {}", meta.len());
    }
    println!("Method = {}", archive_methods(archive).join(" "));
    println!();
    println!("{:>12}  Name", "Size");
    println!("{:-<12}  {:-<40}", "", "");
    for i in 0..archive.num_files() {
        let Some(entry) = listed_entry(archive, i)? else {
            continue;
        };
        if !entry_is_selected(&entry.name, selected) {
            continue;
        }
        println!("{:>12}  {}", entry.size_text, entry.name);
    }
    println!();
    Ok(())
}

fn print_technical_listing(archive: &Archive, selected: &[String]) -> Result<(), CliError> {
    println!("Type = 7z");
    println!("Method = {}", archive_methods(archive).join(" "));
    for i in 0..archive.num_files() {
        let Some(entry) = listed_entry(archive, i)? else {
            continue;
        };
        if !entry_is_selected(&entry.name, selected) {
            continue;
        }
        println!();
        println!("Path = {}", entry.name);
        println!("Size = {}", entry.size_text);
        println!("Folder = {}", entry.kind);
        if let Some(mtime) = entry.mtime {
            println!("Modified = {mtime}");
        }
        if let Some(attrs) = entry.attributes {
            println!("Attributes = {attrs:08X}");
        }
    }
    Ok(())
}

struct ListedEntry {
    name: String,
    size_text: String,
    kind: &'static str,
    mtime: Option<u64>,
    attributes: Option<u32>,
}

fn listed_entry(archive: &Archive, index: usize) -> Result<Option<ListedEntry>, CliError> {
    let fi = archive.files_info();
    let name = fi
        .and_then(|files| files.name(index))
        .unwrap_or_else(|| format!("unknown-{index}"));
    let Some(files) = fi else {
        return Ok(Some(ListedEntry {
            name,
            size_text: "?".to_string(),
            kind: "File",
            mtime: None,
            attributes: None,
        }));
    };
    let kind = if files.is_anti(index) {
        "Anti"
    } else if files.is_directory(index) {
        "Directory"
    } else if files.is_symlink(index) {
        "Symlink"
    } else {
        "File"
    };
    let size_text = if files.is_directory(index) || files.is_anti(index) {
        String::new()
    } else if files.is_empty_file(index) {
        "0".to_string()
    } else {
        archive
            .extract_to_memory(index)
            .map(|bytes| bytes.len().to_string())
            .unwrap_or_else(|_| "?".to_string())
    };
    Ok(Some(ListedEntry {
        name,
        size_text,
        kind,
        mtime: files.mtimes.get(index).copied().flatten(),
        attributes: files.attributes.get(index).copied().flatten(),
    }))
}

fn archive_methods(archive: &Archive) -> Vec<String> {
    let mut names = BTreeSet::new();
    if let Some(streams) = archive.streams_info() {
        if let Some(unpack) = &streams.unpack_info {
            for idx in 0..unpack.num_folders_usize() {
                if let Ok(folder) = unpack.parse_folder(idx) {
                    for coder in folder.coders {
                        let name = method_from_id(&coder.codec_id).map_or_else(
                            || format!("{:02X?}", coder.codec_id),
                            |m| m.name().to_string(),
                        );
                        names.insert(name);
                    }
                }
            }
        }
    }
    if names.is_empty() {
        vec!["Copy".to_string()]
    } else {
        names.into_iter().collect()
    }
}

fn test_archive(cli: &Cli) -> Result<u8, CliError> {
    let archive = open_archive(cli)?;
    let selected = selected_patterns(&cli.operands);
    let mut sink = io::sink();
    let mut warnings = 0u8;
    for i in 0..archive.num_files() {
        let fi = archive.files_info();
        let name = fi
            .and_then(|files| files.name(i))
            .unwrap_or_else(|| format!("unknown-{i}"));
        if !entry_is_selected(&name, &selected) {
            continue;
        }
        if fi.is_some_and(|files| {
            files.is_directory(i) || files.is_anti(i) || files.is_empty_file(i)
        }) {
            continue;
        }
        if let Err(err) =
            archive.extract_to_writer_with_password(i, &mut sink, cli.password.as_deref())
        {
            warnings = EXIT_WARNING;
            eprintln!("Testing entry {i} failed: {err}");
        }
    }
    if warnings == 0 {
        println!("Everything is Ok");
    }
    Ok(warnings)
}

fn extract_archive(cli: &Cli, flat: bool) -> Result<(), CliError> {
    let archive = open_archive(cli)?;
    fs::create_dir_all(&cli.output_dir)?;
    let selected = selected_patterns(&cli.operands);

    for i in 0..archive.num_files() {
        let fi = archive.files_info();
        let name = fi
            .and_then(|files| files.name(i))
            .unwrap_or_else(|| format!("unknown-{i}"));
        if !entry_is_selected(&name, &selected) {
            continue;
        }
        let Some(files) = fi else {
            continue;
        };
        if files.is_anti(i) {
            continue;
        }

        let out_path = if flat {
            let file_name = Path::new(&name)
                .file_name()
                .filter(|part| !part.is_empty())
                .ok_or_else(|| CliError::Fatal(R7zError::UnsafePath(name.clone())))?;
            cli.output_dir.join(file_name)
        } else {
            safe_join(&cli.output_dir, &name)?
        };

        if files.is_directory(i) {
            if !flat {
                fs::create_dir_all(&out_path)?;
            }
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if files.is_empty_file(i) {
            fs::File::create(out_path)?;
        } else {
            let mut file = fs::File::create(out_path)?;
            archive.extract_to_writer_with_password(i, &mut file, cli.password.as_deref())?;
        }
    }
    Ok(())
}

fn create_archive(cli: &Cli, allow_existing_merge: bool) -> Result<(), CliError> {
    if cli.operands.is_empty() {
        return Err(CliError::Usage("no input files were provided".to_string()));
    }
    if allow_existing_merge && cli.archive.exists() {
        return update_archive(cli);
    }
    let paths = expand_disk_patterns(&cli.operands)?;
    let entries = collect_disk_entries(&paths)?;
    write_archive_entries(&cli.archive, entries, &cli.options, &cli.volume_sizes)
}

fn update_archive(cli: &Cli) -> Result<(), CliError> {
    if cli.operands.is_empty() {
        return Err(CliError::Usage("no input files were provided".to_string()));
    }
    if !cli.archive.exists() {
        return create_archive(cli, false);
    }
    let paths = expand_disk_patterns(&cli.operands)?;
    let new_entries = collect_disk_entries(&paths)?;
    let new_names: BTreeSet<String> = new_entries.iter().map(|entry| entry.name.clone()).collect();
    let archive = open_archive(cli)?;
    let mut entries = archive_entries(&archive, cli.password.as_deref())?
        .into_iter()
        .filter(|entry| !new_names.contains(&entry.name))
        .collect::<Vec<_>>();
    entries.extend(new_entries);
    write_archive_entries_atomic(&cli.archive, entries, &cli.options)
}

fn delete_from_archive(cli: &Cli) -> Result<(), CliError> {
    if cli.operands.is_empty() {
        return Err(CliError::Usage(
            "no archive entries were provided".to_string(),
        ));
    }
    let delete_patterns = selected_patterns(&cli.operands);
    let archive = open_archive(cli)?;
    let entries = archive_entries(&archive, cli.password.as_deref())?
        .into_iter()
        .filter(|entry| !entry_is_selected(&entry.name, &delete_patterns))
        .collect::<Vec<_>>();
    write_archive_entries_atomic(&cli.archive, entries, &cli.options)
}

#[derive(Clone)]
struct PendingEntry {
    name: String,
    kind: PendingKind,
    meta: EntryMeta,
}

#[derive(Clone)]
enum PendingKind {
    File(Vec<u8>),
    EmptyFile,
    Directory,
    Anti,
    Symlink(String),
}

fn collect_disk_entries(paths: &[PathBuf]) -> Result<Vec<PendingEntry>, CliError> {
    let mut entries = Vec::new();
    for path in paths {
        let base_name = path
            .file_name()
            .unwrap_or_else(|| OsStr::new(""))
            .to_string_lossy()
            .into_owned();
        if base_name.is_empty() {
            return Err(CliError::Usage(format!(
                "cannot infer archive name for {}",
                path.display()
            )));
        }
        collect_path(path, Path::new(&base_name), &mut entries)?;
    }
    Ok(entries)
}

fn expand_disk_patterns(paths: &[PathBuf]) -> Result<Vec<PathBuf>, CliError> {
    let mut expanded = Vec::new();
    for path in paths {
        let text = path.to_string_lossy();
        if !has_wildcard(&text) {
            expanded.push(path.clone());
            continue;
        }

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
        if parent.is_some_and(|parent| has_wildcard(&parent.to_string_lossy())) {
            return Err(CliError::Usage(format!(
                "wildcards are only supported in the final path component: {}",
                path.display()
            )));
        }
        let parent = parent.unwrap_or_else(|| Path::new("."));
        let pattern = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| CliError::Usage(format!("invalid wildcard path: {}", path.display())))?;

        let mut matches = fs::read_dir(parent)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| wildcard_match(pattern, &entry.file_name().to_string_lossy()))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        matches.sort();
        if matches.is_empty() {
            return Err(CliError::Usage(format!(
                "no input files matched {}",
                path.display()
            )));
        }
        expanded.extend(matches);
    }
    Ok(expanded)
}

fn has_wildcard(text: &str) -> bool {
    text.contains('*') || text.contains('?')
}

fn collect_path(
    path: &Path,
    archive_name: &Path,
    entries: &mut Vec<PendingEntry>,
) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)?;
    let meta = entry_meta_from_fs(&metadata);
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)?.to_string_lossy().into_owned();
        entries.push(PendingEntry {
            name: archive_name_to_string(archive_name)?,
            kind: PendingKind::Symlink(target),
            meta,
        });
    } else if metadata.is_dir() {
        entries.push(PendingEntry {
            name: archive_name_to_string(archive_name)?,
            kind: PendingKind::Directory,
            meta,
        });
        let mut children = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            collect_path(
                &child.path(),
                &archive_name.join(child.file_name()),
                entries,
            )?;
        }
    } else if metadata.is_file() {
        let data = fs::read(path)?;
        let kind = if data.is_empty() {
            PendingKind::EmptyFile
        } else {
            PendingKind::File(data)
        };
        entries.push(PendingEntry {
            name: archive_name_to_string(archive_name)?,
            kind,
            meta,
        });
    }
    Ok(())
}

fn archive_entries(
    archive: &Archive,
    password: Option<&str>,
) -> Result<Vec<PendingEntry>, CliError> {
    let mut entries = Vec::new();
    let Some(files) = archive.files_info() else {
        return Ok(entries);
    };
    for i in 0..archive.num_files() {
        let name = files.name(i).unwrap_or_else(|| format!("unknown-{i}"));
        let meta = entry_meta_from_archive(files, i);
        let kind = if files.is_anti(i) {
            PendingKind::Anti
        } else if files.is_directory(i) {
            PendingKind::Directory
        } else if files.is_symlink(i) {
            let target = archive
                .extract_to_memory_with_password(i, password)
                .and_then(|bytes| String::from_utf8(bytes).map_err(|_| R7zError::Parse))?;
            PendingKind::Symlink(target)
        } else if files.is_empty_file(i) {
            PendingKind::EmptyFile
        } else {
            PendingKind::File(archive.extract_to_memory_with_password(i, password)?)
        };
        entries.push(PendingEntry { name, kind, meta });
    }
    Ok(entries)
}

fn write_archive_entries(
    archive_path: &Path,
    entries: Vec<PendingEntry>,
    options: &ArchiveOptions,
    volume_sizes: &[u64],
) -> Result<(), CliError> {
    if entries.is_empty() {
        return Err(CliError::Usage(
            "cannot create an empty archive".to_string(),
        ));
    }
    let bytes = build_archive_bytes(entries, options)?;
    if volume_sizes.is_empty() {
        fs::write(archive_path, bytes)?;
    } else {
        write_volumes(archive_path, &bytes, volume_sizes)?;
    }
    Ok(())
}

fn write_archive_entries_atomic(
    archive_path: &Path,
    entries: Vec<PendingEntry>,
    options: &ArchiveOptions,
) -> Result<(), CliError> {
    if entries.is_empty() {
        return Err(CliError::Usage(
            "cannot create an empty archive".to_string(),
        ));
    }
    let bytes = build_archive_bytes(entries, options)?;
    let tmp_path = archive_path.with_extension(format!(
        "{}.tmp-{}",
        archive_path
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or("7z"),
        std::process::id()
    ));
    fs::write(&tmp_path, bytes)?;
    fs::rename(&tmp_path, archive_path)?;
    Ok(())
}

fn build_archive_bytes(
    entries: Vec<PendingEntry>,
    options: &ArchiveOptions,
) -> Result<Vec<u8>, CliError> {
    let mut builder = ArchiveBuilder::new().options(options.clone());
    for entry in entries {
        builder = match entry.kind {
            PendingKind::File(data) => {
                builder.add_entry(ArchiveEntry::file(entry.name, entry.meta), Some(&data))?
            }
            PendingKind::EmptyFile => builder.add_empty_file(&entry.name, entry.meta),
            PendingKind::Directory => builder.add_directory(&entry.name, entry.meta),
            PendingKind::Anti => builder.add_anti_item(&entry.name, entry.meta),
            PendingKind::Symlink(target) => builder.add_symlink(&entry.name, &target, entry.meta),
        };
    }
    Ok(builder.build()?)
}

fn write_volumes(base: &Path, bytes: &[u8], sizes: &[u64]) -> Result<(), CliError> {
    let mut offset = 0usize;
    let mut idx = 0usize;
    while offset < bytes.len() {
        let size = usize::try_from(sizes[idx.min(sizes.len() - 1)])
            .map_err(|_| CliError::Usage("volume size is too large".to_string()))?;
        let end = offset.saturating_add(size).min(bytes.len());
        let path = PathBuf::from(format!("{}.{:03}", base.display(), idx + 1));
        fs::write(path, &bytes[offset..end])?;
        offset = end;
        idx += 1;
    }
    Ok(())
}

fn entry_meta_from_archive(files: &r7z::FilesInfo, index: usize) -> EntryMeta {
    EntryMeta {
        ctime: files
            .ctimes
            .get(index)
            .copied()
            .flatten()
            .and_then(filetime_to_system_time),
        atime: files
            .atimes
            .get(index)
            .copied()
            .flatten()
            .and_then(filetime_to_system_time),
        mtime: files
            .mtimes
            .get(index)
            .copied()
            .flatten()
            .and_then(filetime_to_system_time),
        attributes: files.attributes.get(index).copied().flatten(),
        start_pos: files.start_positions.get(index).copied().flatten(),
    }
}

fn entry_meta_from_fs(metadata: &fs::Metadata) -> EntryMeta {
    let mut meta = EntryMeta {
        mtime: metadata.modified().ok(),
        atime: metadata.accessed().ok(),
        ctime: metadata.created().ok(),
        ..EntryMeta::default()
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode();
        meta.attributes = Some((mode << 16) | if metadata.is_dir() { 0x10 } else { 0x20 });
    }
    meta
}

fn filetime_to_system_time(filetime: u64) -> Option<SystemTime> {
    const WINDOWS_TO_UNIX_SECS: u64 = 11_644_473_600;
    let secs = filetime / 10_000_000;
    let nanos = (filetime % 10_000_000) * 100;
    if secs < WINDOWS_TO_UNIX_SECS {
        return None;
    }
    Some(UNIX_EPOCH + Duration::new(secs - WINDOWS_TO_UNIX_SECS, nanos as u32))
}

fn selected_patterns(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .collect()
}

fn entry_is_selected(name: &str, patterns: &[String]) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| wildcard_match(pattern, name))
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.chars().collect::<Vec<_>>();
    let text = text.chars().collect::<Vec<_>>();
    let mut matched = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    matched[0][0] = true;

    for p_idx in 0..pattern.len() {
        for t_idx in 0..=text.len() {
            if !matched[p_idx][t_idx] {
                continue;
            }
            match pattern[p_idx] {
                '*' => {
                    matched[p_idx + 1][t_idx] = true;
                    if t_idx < text.len() {
                        matched[p_idx][t_idx + 1] = true;
                    }
                }
                '?' if t_idx < text.len() => matched[p_idx + 1][t_idx + 1] = true,
                ch if t_idx < text.len() && ch == text[t_idx] => {
                    matched[p_idx + 1][t_idx + 1] = true;
                }
                _ => {}
            }
        }
    }

    matched[pattern.len()][text.len()]
}

fn archive_name_to_string(path: &Path) -> Result<String, CliError> {
    let value = path.to_string_lossy().replace('\\', "/");
    if value.is_empty() {
        Err(CliError::Usage("empty archive entry name".to_string()))
    } else {
        Ok(value)
    }
}

fn safe_join(root: &Path, name: &str) -> Result<PathBuf, CliError> {
    let path = Path::new(name);
    if path.is_absolute() {
        return Err(CliError::Fatal(R7zError::UnsafePath(name.to_string())));
    }
    let mut out = root.to_path_buf();
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return Err(CliError::Fatal(R7zError::UnsafePath(name.to_string()))),
        }
    }
    Ok(out)
}

fn open_archive(cli: &Cli) -> Result<Archive, CliError> {
    Ok(Archive::open_with_password(
        &cli.archive,
        cli.password.as_deref(),
    )?)
}

fn is_help(text: &str) -> bool {
    matches!(text, "-h" | "--help" | "h" | "help")
}

fn usage() -> String {
    "usage: r7z <l|x|e|t|a|d|u> [switches] <archive.7z> [files...]\n\
     switches: -oDIR -pPASS -m0=METHOD -mx=N -ms=on|off -mf=BCJ -mhe=on|off -vSIZE -slt"
        .to_string()
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Fatal(R7zError),
}

impl From<R7zError> for CliError {
    fn from(value: R7zError) -> Self {
        Self::Fatal(value)
    }
}

impl From<io::Error> for CliError {
    fn from(value: io::Error) -> Self {
        Self::Fatal(value.into())
    }
}
