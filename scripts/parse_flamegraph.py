#!/usr/bin/env python3
"""Parse and analyze flamegraph SVGs."""
import sys
import re
from collections import defaultdict

def parse_flamegraph(svg_path):
    """Extract function names and percentages from flamegraph SVG."""
    with open(svg_path, 'r') as f:
        content = f.read()

    entries = []
    # Pattern: "function_name (N samples, X.XX%)"
    pattern = r'<title>([^<]+) \([\d,]+ samples, ([\d.]+)%\)</title>'

    for match in re.finditer(pattern, content):
        name = match.group(1)
        pct = float(match.group(2))

        # Skip generic entries
        if name in ['all', '']:
            continue

        entries.append((name, pct))

    # Sort by percentage descending
    entries.sort(key=lambda x: x[1], reverse=True)
    return entries

def cmd_top(entries, n=20, min_pct=0.5):
    """Show top N functions."""
    print(f"Top {n} functions (>= {min_pct}%):\n")
    print(f"{'%':>7} {'Function':<100}")
    print("-" * 110)

    shown = 0
    total = 0.0

    for name, pct in entries:
        if pct < min_pct:
            continue
        if shown >= n:
            break

        truncated = name if len(name) <= 100 else name[:97] + "..."
        print(f"{pct:>6.2f}% {truncated}")
        total += pct
        shown += 1

    print("-" * 110)
    print(f"{total:>6.2f}% Total ({shown} functions shown)")

def cmd_search(entries, pattern):
    """Search for functions matching pattern."""
    pattern_lower = pattern.lower()
    matches = [(name, pct) for name, pct in entries if pattern_lower in name.lower()]

    if not matches:
        print(f"No functions matching '{pattern}'")
        return

    print(f"Functions matching '{pattern}':\n")
    print(f"{'%':>7} {'Function':<100}")
    print("-" * 110)

    total = 0.0
    for name, pct in matches:
        truncated = name if len(name) <= 100 else name[:97] + "..."
        print(f"{pct:>6.2f}% {truncated}")
        total += pct

    print("-" * 110)
    print(f"{total:>6.2f}% Total ({len(matches)} matches)")

def categorize(name):
    """Categorize function by name."""
    lower = name.lower()

    if 'lzma' in lower or 'compress' in lower or 'decompress' in lower:
        return 'Compression'
    elif 'parse' in lower:
        return 'Parsing'
    elif 'crc' in lower or 'hash' in lower:
        return 'Checksums'
    elif 'alloc' in lower or 'clone' in lower or 'to_vec' in lower:
        return 'Memory'
    elif 'nom' in lower or 'iter' in lower:
        return 'Parsing'
    elif 'criterion' in lower or 'bench' in lower:
        return 'Benchmarking'
    else:
        return 'Other'

def cmd_summary(entries):
    """Show categorized summary."""
    categories = defaultdict(float)

    for name, pct in entries:
        cat = categorize(name)
        categories[cat] += pct

    sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)

    print("Category summary:\n")
    print(f"{'%':>7} {'Category':<50}")
    print("-" * 60)

    for cat, total_pct in sorted_cats:
        print(f"{total_pct:>6.2f}% {cat}")

    print("\n" + "=" * 60)
    print("Top functions by category:\n")

    for cat, _ in sorted_cats:
        funcs = [(name, pct) for name, pct in entries if categorize(name) == cat][:5]
        if funcs:
            print(f"{cat}:")
            for name, pct in funcs:
                truncated = name if len(name) <= 60 else name[:57] + "..."
                print(f"  {pct:>5.2f}% {truncated}")
            print()

def main():
    if len(sys.argv) < 2:
        print("Usage: parse_flamegraph.py <flamegraph.svg> [command] [args...]")
        print("\nCommands:")
        print("  top [N] [min%]     Show top N functions (default: 20, min: 0.5%)")
        print("  search <pattern>   Search for functions matching pattern")
        print("  summary            Show categorized summary")
        sys.exit(1)

    svg_path = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else 'top'

    entries = parse_flamegraph(svg_path)

    if command == 'top':
        n = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        min_pct = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5
        cmd_top(entries, n, min_pct)
    elif command == 'search':
        pattern = sys.argv[3] if len(sys.argv) > 3 else ''
        cmd_search(entries, pattern)
    elif command == 'summary':
        cmd_summary(entries)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()
