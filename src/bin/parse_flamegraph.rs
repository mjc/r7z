use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;

struct Entry {
    name: String,
    samples: u64,
    percent: f64,
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <flamegraph.svg> [command] [args...]", args[0]);
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  top [N] [min%]     Show top N functions (default: 30, min: 1.0%)");
        eprintln!("  search <pattern>   Search for functions matching pattern");
        eprintln!("  syscalls           Show syscall breakdown");
        eprintln!("  summary            Show categorized summary");
        eprintln!("  diff <other.svg>   Compare two flamegraphs (show gained/lost CPU)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} flamegraph.svg top 20", args[0]);
        eprintln!("  {} flamegraph.svg search foyer", args[0]);
        eprintln!("  {} flamegraph.svg syscalls", args[0]);
        eprintln!("  {} flamegraph.svg summary", args[0]);
        eprintln!("  {} before.svg diff after.svg", args[0]);
        std::process::exit(1);
    }

    let svg_path = &args[1];
    let command = args.get(2).map_or("top", String::as_str);

    let content = fs::read_to_string(svg_path)?;
    let entries = parse_entries(&content);

    match command {
        "top" => {
            let n: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(30);
            let min_pct: f64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1.0);
            cmd_top(&entries, n, min_pct);
        }
        "search" => {
            let pattern = args.get(3).map_or("", String::as_str);
            cmd_search(&entries, pattern);
        }
        "syscalls" => {
            cmd_syscalls(&entries);
        }
        "summary" => {
            cmd_summary(&entries);
        }
        "diff" => {
            let Some(other_path) = args.get(3) else {
                eprintln!("Usage: {} <before.svg> diff <after.svg>", args[0]);
                std::process::exit(1);
            };
            let other_content = fs::read_to_string(other_path)?;
            let other_entries = parse_entries(&other_content);
            cmd_diff(&entries, &other_entries);
        }
        _ => {
            eprintln!("Unknown command: {command}");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn parse_entries(content: &str) -> Vec<Entry> {
    let mut results = Vec::new();

    for chunk in content.split("<title>") {
        if let Some(end) = chunk.find("</title>") {
            let title = &chunk[..end];
            if let Some((name, samples, percent)) = parse_title(title) {
                results.push(Entry {
                    name,
                    samples,
                    percent,
                });
            }
        }
    }

    results.sort_by(|a, b| {
        b.percent
            .partial_cmp(&a.percent)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

fn parse_title(title: &str) -> Option<(String, u64, f64)> {
    // Format: "function_name (123,456,789 samples, 12.34%)"
    let paren_start = title.rfind('(')?;
    let name = title[..paren_start].trim().to_string();
    let meta = &title[paren_start + 1..];

    let samples_end = meta.find(" samples")?;
    let samples_str = &meta[..samples_end].replace(',', "");
    let samples: u64 = samples_str.parse().ok()?;

    let pct_start = meta.rfind(", ")? + 2;
    let pct_end = meta.rfind('%')?;
    let percent: f64 = meta[pct_start..pct_end].parse().ok()?;

    if name.is_empty() || name == "all" {
        return None;
    }

    Some((name, samples, percent))
}

fn cmd_top(entries: &[Entry], n: usize, min_pct: f64) {
    println!("Top {n} functions (>= {min_pct:.1}%):\n");
    println!("{:>7} {:>10}  Function", "%", "samples");
    println!("{}", "-".repeat(90));

    let mut shown = 0;
    let mut total = 0.0;

    for e in entries {
        if e.percent < min_pct {
            continue;
        }
        if shown >= n {
            break;
        }

        let display_name = truncate_name(&e.name, 65);
        println!("{:>6.2}% {:>10}  {}", e.percent, e.samples, display_name);
        total += e.percent;
        shown += 1;
    }

    println!("{}", "-".repeat(90));
    println!("{total:>6.2}%             Total ({shown} functions shown)");
}

fn cmd_search(entries: &[Entry], pattern: &str) {
    let pattern_lower = pattern.to_lowercase();
    println!("Functions matching '{pattern}':\n");
    println!("{:>7} {:>10}  Function", "%", "samples");
    println!("{}", "-".repeat(90));

    let mut total = 0.0;
    let mut count = 0;

    for e in entries {
        if e.name.to_lowercase().contains(&pattern_lower) {
            let display_name = truncate_name(&e.name, 65);
            println!("{:>6.2}% {:>10}  {}", e.percent, e.samples, display_name);
            total += e.percent;
            count += 1;
        }
    }

    println!("{}", "-".repeat(90));
    println!("{total:>6.2}%             Total ({count} matches)");
}

fn cmd_syscalls(entries: &[Entry]) {
    println!("Syscall breakdown:\n");
    println!("{:>7}  Syscall", "%");
    println!("{}", "-".repeat(60));

    let mut total = 0.0;

    for e in entries {
        if e.name.starts_with("__x64_sys_") || e.name.starts_with("__x86_sys_") {
            let syscall_name = e
                .name
                .strip_prefix("__x64_sys_")
                .or_else(|| e.name.strip_prefix("__x86_sys_"))
                .unwrap_or(&e.name);
            println!("{:>6.2}%  {}", e.percent, syscall_name);
            total += e.percent;
        }
    }

    println!("{}", "-".repeat(60));
    println!("{total:>6.2}%  Total syscall time");
}

fn cmd_summary(entries: &[Entry]) {
    let mut categories: HashMap<&str, f64> = HashMap::new();

    for e in entries {
        let cat = categorize(&e.name);
        *categories.entry(cat).or_insert(0.0) += e.percent;
    }

    let mut cats: Vec<_> = categories.into_iter().collect();
    cats.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    println!("Category summary:\n");
    println!("{:>7}  Category", "%");
    println!("{}", "-".repeat(40));

    for (cat, pct) in &cats {
        println!("{pct:>6.2}%  {cat}");
    }

    println!("\n{}", "=".repeat(60));
    println!("Key functions by category:\n");

    for cat in &[
        "Cache/Foyer",
        "TLS/Crypto",
        "Network I/O",
        "Disk I/O",
        "Tokio Runtime",
        "Locks/Futex",
        "NNTP Protocol",
        "Compression",
    ] {
        let funcs: Vec<_> = entries
            .iter()
            .filter(|e| categorize(&e.name) == *cat && e.percent >= 0.5)
            .take(5)
            .collect();

        if !funcs.is_empty() {
            println!("{cat}:");
            for e in funcs {
                let short = truncate_name(&e.name, 55);
                println!("  {:>5.2}%  {}", e.percent, short);
            }
            println!();
        }
    }
}

struct Delta<'a> {
    name: &'a str,
    before_pct: f64,
    after_pct: f64,
    diff_pct: f64,
    before_samples: u64,
    after_samples: u64,
}

fn compute_deltas<'a>(before: &'a [Entry], after: &'a [Entry]) -> Vec<Delta<'a>> {
    let before_map: HashMap<&str, (u64, f64)> = before
        .iter()
        .map(|e| (e.name.as_str(), (e.samples, e.percent)))
        .collect();
    let after_map: HashMap<&str, (u64, f64)> = after
        .iter()
        .map(|e| (e.name.as_str(), (e.samples, e.percent)))
        .collect();

    let mut all_names: Vec<&str> = before.iter().map(|e| e.name.as_str()).collect();
    for e in after {
        if !before_map.contains_key(e.name.as_str()) {
            all_names.push(&e.name);
        }
    }

    let mut deltas: Vec<Delta> = all_names
        .iter()
        .filter_map(|name| {
            let (bs, bp) = before_map.get(name).copied().unwrap_or((0, 0.0));
            let (a_s, ap) = after_map.get(name).copied().unwrap_or((0, 0.0));
            let diff = ap - bp;
            (diff.abs() >= 0.01).then_some(Delta {
                name,
                before_pct: bp,
                after_pct: ap,
                diff_pct: diff,
                before_samples: bs,
                after_samples: a_s,
            })
        })
        .collect();

    deltas.sort_by(|a, b| {
        b.diff_pct
            .abs()
            .partial_cmp(&a.diff_pct.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    deltas
}

fn print_delta_table(label: &str, deltas: &[&Delta], limit: usize) {
    println!("{label}:\n");
    println!(
        "{:>8} {:>8} {:>8}  {:>10} {:>10}  Function",
        "before%", "after%", "delta%", "before_n", "after_n"
    );
    println!("{}", "-".repeat(100));
    for d in deltas.iter().take(limit) {
        let display_name = truncate_name(d.name, 42);
        println!(
            "{:>7.2}% {:>7.2}% {:>+7.2}%  {:>10} {:>10}  {display_name}",
            d.before_pct, d.after_pct, d.diff_pct, d.before_samples, d.after_samples,
        );
    }
    println!();
}

fn cmd_diff(before: &[Entry], after: &[Entry]) {
    let deltas = compute_deltas(before, after);
    let regressions: Vec<_> = deltas.iter().filter(|d| d.diff_pct > 0.0).collect();
    let improvements: Vec<_> = deltas.iter().filter(|d| d.diff_pct < 0.0).collect();

    println!("Flamegraph diff: before vs after\n");

    if !regressions.is_empty() {
        print_delta_table("REGRESSIONS (gained CPU)", &regressions, 30);
    }
    if !improvements.is_empty() {
        print_delta_table("IMPROVEMENTS (lost CPU)", &improvements, 30);
    }

    if regressions.is_empty() && improvements.is_empty() {
        println!("No significant differences found (threshold: 0.01%).");
    } else {
        let total_regression: f64 = regressions.iter().map(|d| d.diff_pct).sum();
        let total_improvement: f64 = improvements.iter().map(|d| d.diff_pct).sum();
        println!(
            "Summary: {total_regression:>+.2}% regressions, {total_improvement:>+.2}% improvements ({} functions changed)",
            deltas.len()
        );
    }
}

const CATEGORIES: &[(&str, &[&str])] = &[
    (
        "Cache/Foyer",
        &[
            "foyer",
            "hybrid_cache",
            "hybridarticle",
            "article_cache",
            "unified_cache",
            "cache::",
            "moka",
        ],
    ),
    (
        "NNTP Protocol",
        &[
            "nntp",
            "precheck",
            "article_routing",
            "client_session",
            "backend_execution",
            "command_guard",
            "route_command",
            "status_code",
            "message_id",
        ],
    ),
    (
        "TLS/Crypto",
        &[
            "tls",
            "ssl",
            "rustls",
            "aes",
            "cipher",
            "encrypt",
            "decrypt",
            "handshake",
            "aws_lc",
            "ring::",
            "chacha",
        ],
    ),
    ("Compression", &["lz4", "compress", "decompress", "zstd"]),
    (
        "Connection Pool",
        &["deadpool", "pool", "connection_provider"],
    ),
    (
        "Network I/O",
        &["recv", "send", "tcp", "socket", "inet", "skb", "net_"],
    ),
    (
        "Disk I/O",
        &[
            "zfs",
            "zpl",
            "zil",
            "vfs",
            "write_all",
            "ext4",
            "xfs",
            "btrfs",
            "block_",
            "io_uring",
            "pread",
            "pwrite",
        ],
    ),
    (
        "Locks/Futex",
        &[
            "futex",
            "mutex",
            "lock",
            "rwlock",
            "semaphore",
            "parking_lot",
        ],
    ),
    ("Event Loop", &["epoll", "poll", "mio"]),
    ("Tokio Runtime", &["tokio", "runtime"]),
    ("Async/Futures", &["futures", "async", "waker"]),
    ("Scheduling", &["schedule", "switch", "context"]),
    (
        "Memory",
        &["alloc", "malloc", "free", "mmap", "brk", "jemalloc"],
    ),
];

const SYSCALL_PREFIXES: &[&str] = &["__x64_sys_", "syscall", "do_syscall", "entry_SYSCALL"];

fn categorize(name: &str) -> &'static str {
    let lower = name.to_lowercase();

    for &(category, keywords) in CATEGORIES {
        if keywords.iter().any(|kw| lower.contains(kw)) {
            return category;
        }
    }

    if SYSCALL_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return "Syscall";
    }

    "Other"
}

fn truncate_name(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        format!("{}...", &name[..max_len - 3])
    }
}
