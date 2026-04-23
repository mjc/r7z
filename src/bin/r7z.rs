use chrono::{DateTime, Local};
use r7z::{
    Archive, ArchiveBuilder, ArchiveEntry, ArchiveListing, ArchiveListingEntry, ArchiveOptions,
    Codec, CompressionLevel, EncryptionOptions, EntryMeta, HeaderMode, ListingEntryKind,
    LzmaAlgorithm, MatchFinder, PreservedArchiveEntry, PreservedEntryStream, R7zError,
    RawFolderBlock, SevenZMethod, SolidMode, build_archive_with_preserved_folders,
    method_from_name,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    fs,
    io::{self, IsTerminal, Write},
    num::NonZeroU64,
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
        Err(CliError::FatalMessage(msg)) => {
            eprintln!("Error: {msg}");
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
        Command::ExtractFull => extract_archive(&cli, false),
        Command::ExtractFlat => extract_archive(&cli, true),
        Command::Add => create_archive(&cli, true),
        Command::Update => update_archive(&cli),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OverwriteMode {
    Ask,
    Overwrite,
    SkipExisting,
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
    overwrite_mode: OverwriteMode,
    assume_yes: bool,
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

        let mut state = CliParseState::default();
        let mut positional = Vec::new();

        for arg in args {
            if let Some(switch) = arg.strip_prefix('-') {
                if switch.is_empty() {
                    positional.push(PathBuf::from(arg));
                    continue;
                }
                parse_switch(switch, &mut state)?;
            } else {
                positional.push(PathBuf::from(arg));
            }
        }

        let Some(archive) = positional.first().cloned() else {
            return Err(CliError::Usage("archive path is required".to_string()));
        };
        let operands = positional.into_iter().skip(1).collect();

        if let Some(password) = &state.password {
            let mut encryption = EncryptionOptions::default_for_password(password.clone());
            encryption.encrypt_header = state
                .options
                .encryption
                .as_ref()
                .is_some_and(|enc| enc.encrypt_header);
            state.options.encryption = Some(encryption);
        } else if let Some(encryption) = &state.options.encryption {
            if encryption.encrypt_header {
                return Err(CliError::Usage("-mhe=on requires -pPASS".to_string()));
            }
            state.options.encryption = None;
        }

        if !state.method_was_explicit && state.options.compression.level == CompressionLevel::Store
        {
            state.options.codec = Codec::Copy;
        }

        Ok(Self {
            command,
            archive,
            operands,
            output_dir: state.output_dir,
            password: state.password,
            options: state.options,
            technical: state.technical,
            volume_sizes: state.volume_sizes,
            overwrite_mode: state.overwrite_mode,
            assume_yes: state.assume_yes,
        })
    }
}

struct CliParseState {
    output_dir: PathBuf,
    password: Option<String>,
    options: ArchiveOptions,
    technical: bool,
    method_was_explicit: bool,
    volume_sizes: Vec<u64>,
    overwrite_mode: OverwriteMode,
    assume_yes: bool,
}

impl Default for CliParseState {
    fn default() -> Self {
        Self {
            output_dir: PathBuf::from("."),
            password: None,
            options: ArchiveOptions::default(),
            technical: false,
            method_was_explicit: false,
            volume_sizes: Vec::new(),
            overwrite_mode: OverwriteMode::Ask,
            assume_yes: false,
        }
    }
}

fn parse_switch(switch: &str, state: &mut CliParseState) -> Result<(), CliError> {
    let lower = switch.to_ascii_lowercase();
    if lower == "slt" {
        state.technical = true;
        return Ok(());
    }
    if lower == "y" {
        state.assume_yes = true;
        return Ok(());
    }
    if lower == "bd" {
        return Ok(());
    }
    if lower.starts_with("bb") {
        return parse_log_level_switch(&lower);
    }
    if lower == "aoa" {
        state.overwrite_mode = OverwriteMode::Overwrite;
        return Ok(());
    }
    if lower == "aos" {
        state.overwrite_mode = OverwriteMode::SkipExisting;
        return Ok(());
    }
    if let Some(dir) = switch.strip_prefix('o') {
        if dir.is_empty() {
            return Err(CliError::Usage(
                "-o requires an attached directory".to_string(),
            ));
        }
        state.output_dir = PathBuf::from(dir);
        return Ok(());
    }
    if let Some(pass) = switch.strip_prefix('p') {
        state.password = Some(pass.to_string());
        return Ok(());
    }
    if lower.starts_with("m0=") {
        apply_method_spec(&switch[3..], &mut state.options)?;
        state.method_was_explicit = true;
        return Ok(());
    }
    if lower.starts_with("mc") {
        let value = parse_attached_value(switch, "mc")?;
        state.options.compression.lzma2_chunk_size = Some(parse_chunk_size(value)?);
        return Ok(());
    }
    if lower.starts_with("ma") {
        let value = parse_attached_value(switch, "ma")?;
        state.options.compression.lzma_algorithm = Some(parse_lzma_algorithm(value)?);
        return Ok(());
    }
    if lower.starts_with("mlc") {
        let value = parse_attached_value(switch, "mlc")?;
        state.options.compression.literal_context_bits =
            Some(parse_lzma_property_bits(value, "lc")?);
        validate_lzma_property_bit_combination(&state.options.compression)?;
        return Ok(());
    }
    if lower.starts_with("mlp") {
        let value = parse_attached_value(switch, "mlp")?;
        state.options.compression.literal_position_bits =
            Some(parse_lzma_property_bits(value, "lp")?);
        validate_lzma_property_bit_combination(&state.options.compression)?;
        return Ok(());
    }
    if lower.starts_with("mmf") {
        let value = parse_attached_value(switch, "mmf")?;
        state.options.compression.match_finder = Some(parse_match_finder(value)?);
        return Ok(());
    }
    if lower.starts_with("mmc") {
        let value = parse_attached_value(switch, "mmc")?;
        state.options.compression.match_cycles = Some(parse_match_cycles(value)?);
        return Ok(());
    }
    if lower.starts_with("mpb") {
        let value = parse_attached_value(switch, "mpb")?;
        state.options.compression.position_bits = Some(parse_lzma_property_bits(value, "pb")?);
        return Ok(());
    }
    if lower.starts_with("mmt") {
        return Ok(());
    }
    if lower.starts_with("mx") {
        state.options.compression.level = parse_level(switch)?;
        return Ok(());
    }
    if lower.starts_with("md") {
        let value = parse_attached_value(switch, "md")?;
        let size = parse_size(value)?;
        state.options.compression.dictionary_size = Some(
            u32::try_from(size)
                .map_err(|_| CliError::Usage(format!("dictionary size is too large: {value}")))?,
        );
        return Ok(());
    }
    if lower.starts_with("mfb") {
        let value = parse_attached_value(switch, "mfb")?;
        state.options.compression.fast_bytes = Some(
            value
                .parse::<u32>()
                .map_err(|_| CliError::Usage(format!("invalid fast bytes: {value}")))?,
        );
        return Ok(());
    }
    if lower.starts_with("ms") {
        state.options.compression.solid = parse_solid(switch)?;
        return Ok(());
    }
    if lower.starts_with("mf") {
        parse_filter(switch, &mut state.options)?;
        return Ok(());
    }
    if lower.starts_with("mhe") {
        let enabled = parse_on_off_value(switch, "mhe")?;
        let mut encryption = state
            .options
            .encryption
            .take()
            .unwrap_or_else(|| EncryptionOptions::default_for_password(""));
        encryption.encrypt_header = enabled;
        state.options.header_mode = if enabled {
            HeaderMode::Encoded
        } else {
            state.options.header_mode
        };
        state.options.encryption = Some(encryption);
        return Ok(());
    }
    if let Some(size) = switch.strip_prefix('v') {
        state.volume_sizes.push(parse_size(size)?);
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
        SevenZMethod::Ppmd => Ok(Codec::Ppmd),
        other => Err(CliError::Usage(format!(
            "method {} is tracked for parity but not yet supported by r7z",
            other.name()
        ))),
    }
}

fn apply_method_spec(spec: &str, options: &mut ArchiveOptions) -> Result<(), CliError> {
    let mut parts = spec.split(':');
    let method = parts.next().unwrap_or("");
    options.codec = codec_from_method_name(method)?;
    for param in parts {
        let (key, value) = param
            .split_once('=')
            .ok_or_else(|| CliError::Usage(format!("invalid method option: {param}")))?;
        match key.to_ascii_lowercase().as_str() {
            "d" => {
                let size = parse_size(value)?;
                options.compression.dictionary_size = Some(u32::try_from(size).map_err(|_| {
                    CliError::Usage(format!("dictionary size is too large: {value}"))
                })?);
            }
            "fb" => {
                options.compression.fast_bytes = Some(
                    value
                        .parse::<u32>()
                        .map_err(|_| CliError::Usage(format!("invalid fast bytes: {value}")))?,
                );
            }
            "c" => {
                options.compression.lzma2_chunk_size = Some(parse_chunk_size(value)?);
            }
            "a" => {
                options.compression.lzma_algorithm = Some(parse_lzma_algorithm(value)?);
            }
            "lc" => {
                options.compression.literal_context_bits =
                    Some(parse_lzma_property_bits(value, "lc")?);
            }
            "lp" => {
                options.compression.literal_position_bits =
                    Some(parse_lzma_property_bits(value, "lp")?);
            }
            "pb" => {
                options.compression.position_bits = Some(parse_lzma_property_bits(value, "pb")?);
            }
            "mf" => {
                options.compression.match_finder = Some(parse_match_finder(value)?);
            }
            "mc" => {
                options.compression.match_cycles = Some(parse_match_cycles(value)?);
            }
            "mt" => parse_threading_value(value)?,
            _ => return Err(CliError::Usage(format!("unsupported method option: {key}"))),
        }
    }
    validate_lzma_property_bit_combination(&options.compression)?;
    Ok(())
}

fn parse_lzma_property_bits(value: &str, name: &str) -> Result<u32, CliError> {
    let bits = value
        .parse::<u32>()
        .map_err(|_| CliError::Usage(format!("invalid LZMA {name} value: {value}")))?;
    let max = match name {
        "lc" => 8,
        "lp" | "pb" => 4,
        _ => return Err(CliError::Usage(format!("unknown LZMA property: {name}"))),
    };
    if bits > max {
        return Err(CliError::Usage(format!(
            "invalid LZMA {name} value: {value}; expected 0..={max}"
        )));
    }
    Ok(bits)
}

fn validate_lzma_property_bit_combination(
    compression: &r7z::CompressionOptions,
) -> Result<(), CliError> {
    let lc = compression.literal_context_bits.unwrap_or(3);
    let lp = compression.literal_position_bits.unwrap_or(0);
    if lc + lp > 4 {
        return Err(CliError::Usage(format!(
            "invalid LZMA lc/lp combination: lc + lp must be <= 4 (got {lc} + {lp})"
        )));
    }
    Ok(())
}

fn parse_chunk_size(value: &str) -> Result<NonZeroU64, CliError> {
    let bytes = parse_size_with_label(value, "LZMA2 chunk size")?;
    NonZeroU64::new(bytes)
        .ok_or_else(|| CliError::Usage(format!("invalid LZMA2 chunk size: {value}")))
}

fn parse_lzma_algorithm(value: &str) -> Result<LzmaAlgorithm, CliError> {
    match value {
        "0" => Ok(LzmaAlgorithm::Fast),
        "1" => Ok(LzmaAlgorithm::Normal),
        _ => Err(CliError::Usage(format!(
            "invalid LZMA algorithm value: {value}; expected 0 or 1"
        ))),
    }
}

fn parse_match_cycles(value: &str) -> Result<u32, CliError> {
    let match_cycles = value
        .parse::<u32>()
        .map_err(|_| CliError::Usage(format!("invalid LZMA match cycles: {value}")))?;
    i32::try_from(match_cycles)
        .map_err(|_| CliError::Usage(format!("LZMA match cycles is too large: {value}")))?;
    Ok(match_cycles)
}

fn parse_match_finder(value: &str) -> Result<MatchFinder, CliError> {
    match value.to_ascii_lowercase().as_str() {
        "hc4" => Ok(MatchFinder::Hc4),
        "bt4" => Ok(MatchFinder::Bt4),
        _ => Err(CliError::Usage(format!(
            "invalid LZMA match finder: {value}"
        ))),
    }
}

fn parse_threading_value(value: &str) -> Result<(), CliError> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "off" | "yes" | "no" | "0" => Ok(()),
        value if value.parse::<u64>().is_ok_and(|threads| threads > 0) => Ok(()),
        _ => Err(CliError::Usage(format!(
            "invalid method threading value for mt: {value}"
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

fn parse_log_level_switch(switch: &str) -> Result<(), CliError> {
    match switch {
        "bb" | "bb0" | "bb1" | "bb2" | "bb3" => Ok(()),
        _ => Err(CliError::Usage("-bb expects 0, 1, 2, or 3".to_string())),
    }
}

fn parse_solid(switch: &str) -> Result<SolidMode, CliError> {
    let Some((_, value)) = switch.split_once('=') else {
        return Ok(SolidMode::Solid);
    };
    match value.to_ascii_lowercase().as_str() {
        "on" | "1" | "yes" => Ok(SolidMode::Solid),
        "off" | "0" | "no" => Ok(SolidMode::NonSolid),
        value if value.ends_with('f') => {
            let files = value[..value.len() - 1]
                .parse::<u64>()
                .ok()
                .and_then(NonZeroU64::new)
                .ok_or_else(|| CliError::Usage(format!("invalid solid file limit: {value}")))?;
            Ok(SolidMode::Limit {
                max_files: Some(files),
                max_bytes: None,
            })
        }
        value => {
            let bytes = parse_size_with_label(value, "solid byte limit")?;
            Ok(SolidMode::Limit {
                max_files: None,
                max_bytes: Some(
                    NonZeroU64::new(bytes).expect("parse_size_with_label rejects zero"),
                ),
            })
        }
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
    parse_size_with_label(text, "volume size")
}

fn parse_size_with_label(text: &str, label: &str) -> Result<u64, CliError> {
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
        .map_err(|_| CliError::Usage(format!("invalid {label}: {text}")))?;
    value
        .checked_mul(multiplier)
        .filter(|&value| value > 0)
        .ok_or_else(|| CliError::Usage(format!("invalid {label}: {text}")))
}

fn parse_attached_value<'a>(switch: &'a str, name: &str) -> Result<&'a str, CliError> {
    let value = switch
        .get(name.len()..)
        .ok_or_else(|| CliError::Usage(format!("-{name} requires a value")))?;
    let value = value.strip_prefix('=').unwrap_or(value);
    if value.is_empty() {
        Err(CliError::Usage(format!("-{name} requires a value")))
    } else {
        Ok(value)
    }
}

fn list_archive(cli: &Cli) -> Result<(), CliError> {
    let archive = open_archive(cli)?;
    let physical_size = fs::metadata(&cli.archive).ok().map(|meta| meta.len());
    let listing = archive.listing(physical_size)?;
    let selected = selected_patterns(&cli.operands);
    if cli.technical {
        print_technical_listing(&listing, &cli.archive, &selected);
    } else {
        print_listing(&listing, &cli.archive, &selected);
    }
    Ok(())
}

fn print_listing(listing: &ArchiveListing, archive_path: &Path, selected: &[String]) {
    println!();
    print_listing_header(listing, archive_path);
    println!();
    println!("   Date      Time    Attr         Size   Compressed  Name");
    println!("------------------- ----- ------------ ------------  ------------------------");
    let mut total_size = 0u64;
    let mut total_packed = 0u64;
    let mut file_count = 0usize;
    let mut folder_count = 0usize;
    let mut summary_time = None;

    for entry in listing
        .entries
        .iter()
        .filter(|entry| entry_is_selected(&entry.path, selected))
    {
        if matches!(entry.kind, ListingEntryKind::Anti) {
            continue;
        };
        if matches!(entry.kind, ListingEntryKind::Directory) {
            folder_count += 1;
        } else {
            file_count += 1;
        };
        total_size += entry.size.unwrap_or(0);
        total_packed += entry_packed_for_summary(entry);
        summary_time = newest_time(summary_time, entry.modified);
        println!(
            "{:19} {:5} {:>12} {:>12}  {}",
            format_listing_time(entry.modified),
            human_attributes(entry),
            size_text(entry.size),
            size_text(entry_packed_for_row(entry)),
            entry.path
        );
    }
    println!("------------------- ----- ------------ ------------  ------------------------");
    println!(
        "{:19} {:5} {:>12} {:>12}  {}",
        format_listing_time(summary_time),
        "",
        total_size,
        total_packed,
        summary_text(file_count, folder_count)
    );
    println!();
}

fn print_technical_listing(listing: &ArchiveListing, archive_path: &Path, selected: &[String]) {
    print_listing_header(listing, archive_path);
    println!();
    println!("----------");
    for entry in listing
        .entries
        .iter()
        .filter(|entry| entry_is_selected(&entry.path, selected))
    {
        println!("Path = {}", entry.path);
        println!("Size = {}", size_text(entry.size));
        println!("Packed Size = {}", size_text(entry_packed_for_row(entry)));
        println!("Modified = {}", format_listing_time(entry.modified));
        if let Some(attrs) = technical_attributes(entry) {
            println!("Attributes = {attrs}");
        }
        if let Some(crc) = entry.crc {
            println!("CRC = {crc:08X}");
        } else if !matches!(entry.kind, ListingEntryKind::Anti) {
            println!("CRC = ");
        }
        println!("Encrypted = {}", if entry.encrypted { "+" } else { "-" });
        println!("Method = {}", entry.methods.join(" "));
        println!(
            "Block = {}",
            entry
                .block
                .map_or_else(String::new, |block| block.to_string())
        );
        println!();
    }
}

fn print_listing_header(listing: &ArchiveListing, archive_path: &Path) {
    println!("Path = {}", archive_path.display());
    println!("Type = {}", listing.archive_type);
    if let Some(size) = listing.physical_size {
        println!("Physical Size = {size}");
    }
    if let Some(size) = listing.headers_size {
        println!("Headers Size = {size}");
    }
    if !listing.methods.is_empty() {
        println!("Method = {}", listing.methods.join(" "));
    }
    println!("Solid = {}", if listing.solid { "+" } else { "-" });
    println!("Blocks = {}", listing.blocks);
}

fn size_text(size: Option<u64>) -> String {
    size.map_or_else(String::new, |size| size.to_string())
}

fn entry_packed_for_row(entry: &ArchiveListingEntry) -> Option<u64> {
    if matches!(entry.kind, ListingEntryKind::Directory) || entry.size == Some(0) {
        Some(0)
    } else {
        entry.packed_size
    }
}

fn entry_packed_for_summary(entry: &ArchiveListingEntry) -> u64 {
    if matches!(entry.kind, ListingEntryKind::Anti) {
        0
    } else {
        entry_packed_for_row(entry).unwrap_or(0)
    }
}

fn newest_time(left: Option<SystemTime>, right: Option<SystemTime>) -> Option<SystemTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn format_listing_time(time: Option<SystemTime>) -> String {
    time.map_or_else(String::new, |time| {
        let datetime: DateTime<Local> = time.into();
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    })
}

fn human_attributes(entry: &ArchiveListingEntry) -> &'static str {
    if entry.attributes.is_none() {
        return ".....";
    }
    match entry.kind {
        ListingEntryKind::Directory => "D....",
        ListingEntryKind::File | ListingEntryKind::Symlink => "....A",
        ListingEntryKind::Anti => ".....",
    }
}

fn technical_attributes(entry: &ArchiveListingEntry) -> Option<String> {
    if matches!(entry.kind, ListingEntryKind::Anti) {
        return None;
    }
    let class = match entry.kind {
        ListingEntryKind::Directory => "D",
        ListingEntryKind::File | ListingEntryKind::Symlink => "A",
        ListingEntryKind::Anti => unreachable!(),
    };
    let attrs = entry.attributes?;
    let mode = attrs >> 16;
    if mode == 0 {
        return Some(format!("{class} {attrs:08X}"));
    }
    let mode_text = unix_mode_text(mode);
    let separator = if matches!(entry.kind, ListingEntryKind::Symlink) {
        ""
    } else {
        "_"
    };
    Some(format!("{class}{separator} {mode_text}"))
}

fn unix_mode_text(mode: u32) -> String {
    let kind = match mode & 0o170_000 {
        0o040_000 => 'd',
        0o120_000 => 'l',
        _ => '-',
    };
    let mut text = String::with_capacity(10);
    text.push(kind);
    for bit in [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ] {
        text.push(match bit {
            0o400 | 0o040 | 0o004 => {
                if mode & bit != 0 {
                    'r'
                } else {
                    '-'
                }
            }
            0o200 | 0o020 | 0o002 => {
                if mode & bit != 0 {
                    'w'
                } else {
                    '-'
                }
            }
            _ => {
                if mode & bit != 0 {
                    'x'
                } else {
                    '-'
                }
            }
        });
    }
    text
}

fn summary_text(files: usize, folders: usize) -> String {
    match (files, folders) {
        (files, 0) => format!("{files} files"),
        (0, folders) => format!("{folders} folders"),
        (files, folders) => format!("{files} files, {folders} folders"),
    }
}

fn test_archive(cli: &Cli) -> Result<u8, CliError> {
    let archive = open_archive(cli)?;
    let selected = selected_patterns(&cli.operands);
    let mut sink = io::sink();
    let mut warnings = 0u8;
    let mut matched = 0usize;
    for i in 0..archive.num_files() {
        let fi = archive.files_info();
        let name = fi
            .and_then(|files| files.name(i))
            .unwrap_or_else(|| format!("unknown-{i}"));
        if !entry_is_selected(&name, &selected) {
            continue;
        }
        matched += 1;
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
    if !selected.is_empty() && matched == 0 {
        eprintln!("No files to process");
        return Ok(EXIT_WARNING);
    }
    if warnings == 0 {
        println!("Everything is Ok");
    }
    Ok(warnings)
}

fn extract_archive(cli: &Cli, flat: bool) -> Result<u8, CliError> {
    let mut ui = TerminalOverwriteUi;
    extract_archive_with_ui(cli, flat, &mut ui)
}

fn extract_archive_with_ui(
    cli: &Cli,
    flat: bool,
    ui: &mut impl OverwriteUi,
) -> Result<u8, CliError> {
    let archive = open_archive(cli)?;
    fs::create_dir_all(&cli.output_dir)?;
    let selected = selected_patterns(&cli.operands);
    let mut matched = 0usize;
    let mut warnings = 0u8;
    let mut overwrite_mode = cli.overwrite_mode;

    for i in 0..archive.num_files() {
        let fi = archive.files_info();
        let name = fi
            .and_then(|files| files.name(i))
            .unwrap_or_else(|| format!("unknown-{i}"));
        if !entry_is_selected(&name, &selected) {
            continue;
        }
        matched += 1;
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
                if out_path.exists() && !out_path.is_dir() {
                    match decide_overwrite(&mut overwrite_mode, cli.assume_yes, ui, &out_path)? {
                        CollisionAction::Overwrite => fs::remove_file(&out_path)?,
                        CollisionAction::Skip { warning } => {
                            if warning {
                                warnings = EXIT_WARNING;
                            }
                            continue;
                        }
                        CollisionAction::Quit => return Ok(EXIT_WARNING),
                    }
                }
                fs::create_dir_all(&out_path)?;
            }
            continue;
        }

        if out_path.exists() {
            if out_path.is_dir() {
                ui.warn_skip_existing(&out_path)?;
                warnings = EXIT_WARNING;
                continue;
            }
            match decide_overwrite(&mut overwrite_mode, cli.assume_yes, ui, &out_path)? {
                CollisionAction::Overwrite => fs::remove_file(&out_path)?,
                CollisionAction::Skip { warning } => {
                    if warning {
                        warnings = EXIT_WARNING;
                    }
                    continue;
                }
                CollisionAction::Quit => return Ok(EXIT_WARNING),
            }
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
    if !selected.is_empty() && matched == 0 {
        eprintln!("No files to process");
        Ok(EXIT_WARNING)
    } else {
        Ok(warnings)
    }
}

trait OverwriteUi {
    fn is_interactive(&self) -> bool;
    fn prompt_overwrite(&mut self, path: &Path) -> Result<OverwriteAnswer, CliError>;
    fn warn_skip_existing(&mut self, path: &Path) -> Result<(), CliError>;
}

struct TerminalOverwriteUi;

impl OverwriteUi for TerminalOverwriteUi {
    fn is_interactive(&self) -> bool {
        io::stdin().is_terminal()
    }

    fn prompt_overwrite(&mut self, path: &Path) -> Result<OverwriteAnswer, CliError> {
        loop {
            eprint!(
                "Overwrite {}? [y]es/[n]o/[a]ll/[s]kip all/[q]uit: ",
                path.display()
            );
            io::stderr().flush()?;
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            if let Some(answer) = parse_overwrite_answer(&answer) {
                return Ok(answer);
            }
            eprintln!("Invalid response");
        }
    }

    fn warn_skip_existing(&mut self, path: &Path) -> Result<(), CliError> {
        eprintln!("WARNING: Skipping existing path: {}", path.display());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OverwriteAnswer {
    Yes,
    No,
    All,
    SkipAll,
    Quit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CollisionAction {
    Overwrite,
    Skip { warning: bool },
    Quit,
}

fn decide_overwrite(
    mode: &mut OverwriteMode,
    assume_yes: bool,
    ui: &mut impl OverwriteUi,
    path: &Path,
) -> Result<CollisionAction, CliError> {
    match *mode {
        OverwriteMode::Overwrite => Ok(CollisionAction::Overwrite),
        OverwriteMode::SkipExisting => Ok(CollisionAction::Skip { warning: false }),
        OverwriteMode::Ask if assume_yes => Ok(CollisionAction::Overwrite),
        OverwriteMode::Ask if !ui.is_interactive() => {
            ui.warn_skip_existing(path)?;
            Ok(CollisionAction::Skip { warning: true })
        }
        OverwriteMode::Ask => match ui.prompt_overwrite(path)? {
            OverwriteAnswer::Yes => Ok(CollisionAction::Overwrite),
            OverwriteAnswer::No => {
                ui.warn_skip_existing(path)?;
                Ok(CollisionAction::Skip { warning: true })
            }
            OverwriteAnswer::All => {
                *mode = OverwriteMode::Overwrite;
                Ok(CollisionAction::Overwrite)
            }
            OverwriteAnswer::SkipAll => {
                *mode = OverwriteMode::SkipExisting;
                ui.warn_skip_existing(path)?;
                Ok(CollisionAction::Skip { warning: true })
            }
            OverwriteAnswer::Quit => Ok(CollisionAction::Quit),
        },
    }
}

fn parse_overwrite_answer(input: &str) -> Option<OverwriteAnswer> {
    match input.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Some(OverwriteAnswer::Yes),
        "" | "n" | "no" => Some(OverwriteAnswer::No),
        "a" | "all" => Some(OverwriteAnswer::All),
        "s" | "skip" | "skip all" => Some(OverwriteAnswer::SkipAll),
        "q" | "quit" => Some(OverwriteAnswer::Quit),
        _ => None,
    }
}

fn create_archive(cli: &Cli, allow_existing_merge: bool) -> Result<u8, CliError> {
    if cli.operands.is_empty() {
        return Err(CliError::Usage("no input files were provided".to_string()));
    }
    if allow_existing_merge && cli.archive.exists() {
        return update_archive(cli);
    }
    let scan = scan_disk_operands(&cli.operands)?;
    let paths = scan.paths;
    let entries = collect_disk_entries(&paths)?;
    write_archive_entries(&cli.archive, entries, &cli.options, &cli.volume_sizes)?;
    print_scan_warnings(&scan.warnings);
    Ok(if scan.warnings.is_empty() {
        EXIT_OK
    } else {
        EXIT_WARNING
    })
}

fn update_archive(cli: &Cli) -> Result<u8, CliError> {
    if cli.operands.is_empty() {
        return Err(CliError::Usage("no input files were provided".to_string()));
    }
    if !cli.archive.exists() {
        return create_archive(cli, false);
    }
    let scan = scan_disk_operands(&cli.operands)?;
    let paths = scan.paths;
    let new_entries = collect_disk_entries(&paths)?;
    let new_names: BTreeSet<String> = new_entries.iter().map(|entry| entry.name.clone()).collect();
    let archive = open_archive(cli)?;
    let (entries, raw_folders) = preserved_rewrite_entries(
        &archive,
        cli.password.as_deref(),
        |name| new_names.contains(name),
        new_entries,
    )?;
    write_preserved_archive_entries_atomic(&cli.archive, entries, raw_folders, &cli.options)?;
    print_scan_warnings(&scan.warnings);
    Ok(if scan.warnings.is_empty() {
        EXIT_OK
    } else {
        EXIT_WARNING
    })
}

fn delete_from_archive(cli: &Cli) -> Result<(), CliError> {
    if cli.operands.is_empty() {
        return Err(CliError::Usage(
            "no archive entries were provided".to_string(),
        ));
    }
    let delete_patterns = selected_patterns(&cli.operands);
    let archive = open_archive(cli)?;
    let (entries, raw_folders) = preserved_rewrite_entries(
        &archive,
        cli.password.as_deref(),
        |name| entry_is_selected(name, &delete_patterns),
        Vec::new(),
    )?;
    write_preserved_archive_entries_atomic(&cli.archive, entries, raw_folders, &cli.options)
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

struct DiskScan {
    paths: Vec<PathBuf>,
    warnings: Vec<DiskScanWarning>,
}

struct DiskScanWarning {
    path: PathBuf,
}

fn scan_disk_operands(paths: &[PathBuf]) -> Result<DiskScan, CliError> {
    let mut expanded = Vec::new();
    let mut warnings = Vec::new();
    for path in paths {
        let text = path.to_string_lossy();
        if !has_wildcard(&text) {
            match fs::symlink_metadata(path) {
                Ok(_) => expanded.push(path.clone()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    warnings.push(DiskScanWarning { path: path.clone() });
                }
                Err(err) => return Err(err.into()),
            }
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

        let entries = match fs::read_dir(parent) {
            Ok(entries) => entries.collect::<Result<Vec<_>, _>>()?,
            Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(err) => return Err(err.into()),
        };
        let mut matches = entries
            .into_iter()
            .filter(|entry| wildcard_match(pattern, &entry.file_name().to_string_lossy()))
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        matches.sort();
        expanded.extend(matches);
    }
    Ok(DiskScan {
        paths: expanded,
        warnings,
    })
}

fn print_scan_warnings(warnings: &[DiskScanWarning]) {
    if warnings.is_empty() {
        return;
    }
    eprintln!();
    eprintln!("Scan WARNINGS for files and folders:");
    eprintln!();
    for warning in warnings {
        eprintln!(
            "{} : errno=2 : No such file or directory",
            warning.path.display()
        );
    }
    eprintln!("----------------");
    eprintln!("Scan WARNINGS: {}", warnings.len());
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

fn preserved_rewrite_entries(
    archive: &Archive,
    password: Option<&str>,
    should_drop: impl Fn(&str) -> bool,
    append_entries: Vec<PendingEntry>,
) -> Result<(Vec<PreservedArchiveEntry>, Vec<RawFolderBlock>), CliError> {
    let Some(files) = archive.files_info() else {
        return Ok((
            append_entries
                .into_iter()
                .map(pending_to_preserved_entry)
                .collect(),
            Vec::new(),
        ));
    };
    let listing = archive.listing(None)?;
    let mut listing_by_index: Vec<Option<&ArchiveListingEntry>> = vec![None; archive.num_files()];
    for entry in &listing.entries {
        if let Some(slot) = listing_by_index.get_mut(entry.index) {
            *slot = Some(entry);
        }
    }

    let mut retained = vec![false; archive.num_files()];
    let mut folder_entries: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, is_retained) in retained.iter_mut().enumerate().take(archive.num_files()) {
        let name = files.name(i).unwrap_or_else(|| format!("unknown-{i}"));
        *is_retained = !should_drop(&name);
        if let Some(block) = listing_by_index
            .get(i)
            .and_then(|entry| entry.and_then(|entry| entry.block))
        {
            folder_entries.entry(block).or_default().push(i);
        }
    }

    let mut raw_folder_ids = BTreeSet::new();
    let mut decode_indices = BTreeSet::new();
    for (folder, indices) in &folder_entries {
        let retained_count = indices.iter().filter(|&&idx| retained[idx]).count();
        if retained_count == indices.len() {
            raw_folder_ids.insert(*folder);
        } else if retained_count > 0 {
            decode_indices.extend(indices.iter().copied().filter(|&idx| retained[idx]));
        }
    }

    let raw_folders = raw_folder_ids
        .iter()
        .map(|&folder| archive.raw_folder_block(folder))
        .collect::<Result<Vec<_>, _>>()?;

    let mut entries = Vec::new();
    for (i, is_retained) in retained.iter().enumerate().take(archive.num_files()) {
        if !is_retained {
            continue;
        }
        let listing_entry = listing_by_index
            .get(i)
            .and_then(|entry| *entry)
            .ok_or(R7zError::Parse)?;
        let name = files.name(i).unwrap_or_else(|| format!("unknown-{i}"));
        let meta = entry_meta_from_archive(files, i);
        let kind = preserved_entry_kind(files, i);
        let stream = if let Some(folder) = listing_entry.block {
            if raw_folder_ids.contains(&folder) {
                PreservedEntryStream::Raw {
                    folder_id: folder,
                    size: listing_entry.size.ok_or(R7zError::Parse)?,
                    crc: listing_entry.crc,
                }
            } else if decode_indices.contains(&i) {
                match archive.extract_to_memory_with_password(i, password) {
                    Ok(data) => PreservedEntryStream::Data(data),
                    Err(
                        err @ (R7zError::UnsupportedCodec(_)
                        | R7zError::PasswordRequired
                        | R7zError::Decompression
                        | R7zError::Crc),
                    ) => {
                        return Err(CliError::FatalMessage(format!(
                            "operation would require decoding retained entry '{name}' in a partially changed archive folder: {err}"
                        )));
                    }
                    Err(err) => return Err(err.into()),
                }
            } else {
                return Err(R7zError::Parse.into());
            }
        } else {
            PreservedEntryStream::None
        };
        entries.push(PreservedArchiveEntry {
            name,
            kind,
            meta,
            stream,
        });
    }
    entries.extend(append_entries.into_iter().map(pending_to_preserved_entry));
    Ok((entries, raw_folders))
}

fn preserved_entry_kind(files: &r7z::FilesInfo, index: usize) -> r7z::EntryKind {
    if files.is_anti(index) {
        r7z::EntryKind::Anti
    } else if files.is_directory(index) {
        r7z::EntryKind::Directory
    } else {
        r7z::EntryKind::File
    }
}

fn pending_to_preserved_entry(entry: PendingEntry) -> PreservedArchiveEntry {
    let PendingEntry { name, kind, meta } = entry;
    let (kind, stream) = match kind {
        PendingKind::File(data) => (r7z::EntryKind::File, PreservedEntryStream::Data(data)),
        PendingKind::EmptyFile => (r7z::EntryKind::File, PreservedEntryStream::None),
        PendingKind::Directory => (r7z::EntryKind::Directory, PreservedEntryStream::None),
        PendingKind::Symlink(target) => (
            r7z::EntryKind::File,
            PreservedEntryStream::Data(target.into_bytes()),
        ),
    };
    PreservedArchiveEntry {
        name,
        kind,
        meta,
        stream,
    }
}

fn write_archive_entries(
    archive_path: &Path,
    entries: Vec<PendingEntry>,
    options: &ArchiveOptions,
    volume_sizes: &[u64],
) -> Result<(), CliError> {
    let bytes = build_archive_bytes(entries, options)?;
    if volume_sizes.is_empty() {
        fs::write(archive_path, bytes)?;
    } else {
        write_volumes(archive_path, &bytes, volume_sizes)?;
    }
    Ok(())
}

fn write_preserved_archive_entries_atomic(
    archive_path: &Path,
    entries: Vec<PreservedArchiveEntry>,
    raw_folders: Vec<RawFolderBlock>,
    options: &ArchiveOptions,
) -> Result<(), CliError> {
    let bytes = build_archive_with_preserved_folders(entries, raw_folders, options)?;
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
     switches: -oDIR -pPASS -m0=METHOD -mx=N -ms=on|off -mf=BCJ -mhe=on|off -vSIZE -aoa|-aos -slt"
        .to_string()
}

#[derive(Debug)]
enum CliError {
    Usage(String),
    Fatal(R7zError),
    FatalMessage(String),
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

#[cfg(test)]
mod tests {
    use super::{
        CollisionAction, OverwriteAnswer, OverwriteMode, OverwriteUi, decide_overwrite,
        parse_overwrite_answer,
    };
    use std::{collections::VecDeque, path::Path};

    #[test]
    fn parse_overwrite_answers_matches_p7zip_prompt_words() {
        for input in ["y", "yes", "YES"] {
            assert_eq!(parse_overwrite_answer(input), Some(OverwriteAnswer::Yes));
        }
        for input in ["", "n", "no"] {
            assert_eq!(parse_overwrite_answer(input), Some(OverwriteAnswer::No));
        }
        for input in ["a", "all"] {
            assert_eq!(parse_overwrite_answer(input), Some(OverwriteAnswer::All));
        }
        for input in ["s", "skip", "skip all"] {
            assert_eq!(
                parse_overwrite_answer(input),
                Some(OverwriteAnswer::SkipAll)
            );
        }
        for input in ["q", "quit"] {
            assert_eq!(parse_overwrite_answer(input), Some(OverwriteAnswer::Quit));
        }
        assert_eq!(parse_overwrite_answer("maybe"), None);
    }

    #[test]
    fn overwrite_policy_noninteractive_ask_skips_with_warning() {
        let mut ui = FakeOverwriteUi::noninteractive([]);
        let mut mode = OverwriteMode::Ask;

        let action = decide_overwrite(&mut mode, false, &mut ui, Path::new("exists.txt")).unwrap();

        assert_eq!(action, CollisionAction::Skip { warning: true });
        assert_eq!(mode, OverwriteMode::Ask);
        assert_eq!(ui.warned, vec!["exists.txt"]);
        assert!(ui.prompts.is_empty());
    }

    #[test]
    fn overwrite_policy_assume_yes_overwrites_without_prompt() {
        let mut ui = FakeOverwriteUi::noninteractive([]);
        let mut mode = OverwriteMode::Ask;

        let action = decide_overwrite(&mut mode, true, &mut ui, Path::new("exists.txt")).unwrap();

        assert_eq!(action, CollisionAction::Overwrite);
        assert_eq!(mode, OverwriteMode::Ask);
        assert!(ui.warned.is_empty());
        assert!(ui.prompts.is_empty());
    }

    #[test]
    fn overwrite_policy_all_switches_later_collisions_to_overwrite() {
        let mut ui = FakeOverwriteUi::interactive([OverwriteAnswer::All]);
        let mut mode = OverwriteMode::Ask;

        let first = decide_overwrite(&mut mode, false, &mut ui, Path::new("first.txt")).unwrap();
        let second = decide_overwrite(&mut mode, false, &mut ui, Path::new("second.txt")).unwrap();

        assert_eq!(first, CollisionAction::Overwrite);
        assert_eq!(second, CollisionAction::Overwrite);
        assert_eq!(mode, OverwriteMode::Overwrite);
        assert_eq!(ui.prompts, vec!["first.txt"]);
        assert!(ui.warned.is_empty());
    }

    #[test]
    fn overwrite_policy_skip_all_switches_later_collisions_to_silent_skip() {
        let mut ui = FakeOverwriteUi::interactive([OverwriteAnswer::SkipAll]);
        let mut mode = OverwriteMode::Ask;

        let first = decide_overwrite(&mut mode, false, &mut ui, Path::new("first.txt")).unwrap();
        let second = decide_overwrite(&mut mode, false, &mut ui, Path::new("second.txt")).unwrap();

        assert_eq!(first, CollisionAction::Skip { warning: true });
        assert_eq!(second, CollisionAction::Skip { warning: false });
        assert_eq!(mode, OverwriteMode::SkipExisting);
        assert_eq!(ui.prompts, vec!["first.txt"]);
        assert_eq!(ui.warned, vec!["first.txt"]);
    }

    #[test]
    fn overwrite_policy_quit_stops_without_warning_side_effect() {
        let mut ui = FakeOverwriteUi::interactive([OverwriteAnswer::Quit]);
        let mut mode = OverwriteMode::Ask;

        let action = decide_overwrite(&mut mode, false, &mut ui, Path::new("exists.txt")).unwrap();

        assert_eq!(action, CollisionAction::Quit);
        assert_eq!(mode, OverwriteMode::Ask);
        assert_eq!(ui.prompts, vec!["exists.txt"]);
        assert!(ui.warned.is_empty());
    }

    struct FakeOverwriteUi {
        interactive: bool,
        answers: VecDeque<OverwriteAnswer>,
        prompts: Vec<String>,
        warned: Vec<String>,
    }

    impl FakeOverwriteUi {
        fn interactive(answers: impl IntoIterator<Item = OverwriteAnswer>) -> Self {
            Self {
                interactive: true,
                answers: answers.into_iter().collect(),
                prompts: Vec::new(),
                warned: Vec::new(),
            }
        }

        fn noninteractive(answers: impl IntoIterator<Item = OverwriteAnswer>) -> Self {
            Self {
                interactive: false,
                answers: answers.into_iter().collect(),
                prompts: Vec::new(),
                warned: Vec::new(),
            }
        }
    }

    impl OverwriteUi for FakeOverwriteUi {
        fn is_interactive(&self) -> bool {
            self.interactive
        }

        fn prompt_overwrite(&mut self, path: &Path) -> Result<OverwriteAnswer, super::CliError> {
            self.prompts.push(path.display().to_string());
            self.answers.pop_front().ok_or_else(|| {
                super::CliError::Usage("fake overwrite UI ran out of answers".to_string())
            })
        }

        fn warn_skip_existing(&mut self, path: &Path) -> Result<(), super::CliError> {
            self.warned.push(path.display().to_string());
            Ok(())
        }
    }
}
