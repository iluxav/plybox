#!/usr/bin/env python3
"""Summarize raw trials: median [minimum–maximum], never pooled percentiles."""
import json
from pathlib import Path
import statistics
import sys

from run import CASES, TIERS

FIELDS = {
    "p50_ms": ("Request p50 (ms)", 1),
    "p99_ms": ("Request p99 (ms)", 1),
    "requests_s": ("Requests/s", 1),
    "cpu_ms_request": ("Whole-box CPU ms/request", 1),
    "MB_s": ("Payload MB/s (decimal)", 1),
    "cpu_seconds_GB": ("Whole-box CPU seconds/GB", 1),
    "seconds": ("Work time (s)", 1),
    "cpu_seconds": ("Whole-box CPU (s)", 1),
    "rss_bytes": ("Summed RSS (MiB)", 1 / 2**20),
    "pss_bytes": ("Summed PSS (MiB)", 1 / 2**20),
    "memory_current_bytes": ("Cgroup memory.current (MiB)", 1 / 2**20),
}


def main():
    out = Path(sys.argv[1])
    rows = [json.loads(line) for line in (out / "raw.jsonl").read_text().splitlines()]
    machine = json.loads((out / "machine.json").read_text())
    summary = {}
    lines = [f"# Warm whole-box benchmark: {machine['utc']}", "",
             "Each cell is the median [min–max] across trials. Latency percentiles",
             "are calculated within each trial, then summarized across trials.", ""]
    for case in CASES:
        group = [r for r in rows if r["case"] == case]
        if not group:
            continue
        counts = {tier: sum(r["tier"] == tier for r in group) for tier in TIERS}
        lines += [f"## {case}", "", f"Trials: {counts}.", "", "| Metric | Host | Namespace | gVisor |",
                  "|---|---:|---:|---:|"]
        summary[case] = {}
        for field, (label, scale) in FIELDS.items():
            if not any(field in r["metrics"] for r in group):
                continue
            if case.startswith("idle") and field == "cpu_seconds":
                label, scale = "Whole-box CPU (ms)", 1000
            cells = []
            for tier in TIERS:
                values = [r["metrics"].get(field) for r in group if r["tier"] == tier]
                if not values or any(value is None for value in values):
                    cells.append("unavailable")
                    continue
                stats = {"median": statistics.median(values), "min": min(values), "max": max(values), "n": len(values)}
                summary[case].setdefault(tier, {})[field] = stats
                cells.append(f"{stats['median'] * scale:.3f} [{stats['min'] * scale:.3f}–{stats['max'] * scale:.3f}]")
            lines.append(f"| {label} | " + " | ".join(cells) + " |")
        if case in ["cpu", "files"]:
            for field in ["seconds", "cpu_seconds"]:
                baseline = summary[case].get("host", {}).get(field, {}).get("median")
                if baseline:
                    cells = [f"{summary[case][tier][field]['median'] / baseline:.3f}×" if field in summary[case].get(tier, {}) else "unavailable" for tier in TIERS]
                    lines.append(f"| {'Time' if field == 'seconds' else 'CPU'} / host median | " + " | ".join(cells) + " |")
        lines.append("")
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (out / "report.md").write_text("\n".join(lines))
    print(f"report: {out / 'report.md'}", flush=True)


if __name__ == "__main__":
    main()
