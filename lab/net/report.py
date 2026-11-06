#!/usr/bin/env python3
"""plybox lab step 2 report: network probes + workloads for one box run.

    report.py <results-dir>
"""
import sys
from pathlib import Path

CELL = {"ALLOWED": "OPEN", "BLOCKED": "closed", "NA": "n/a"}


def load_probe(path):
    rows = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        p = line.split("\t")
        if p and p[0] == "probe" and len(p) >= 3:
            rows[p[1]] = (p[2], p[3] if len(p) > 3 else "")
    return rows


def load_host(path):
    rows = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        p = line.split("\t", 2)
        if len(p) >= 2:
            rows[p[0]] = (p[1], p[2] if len(p) > 2 else "")
    return rows


def load_workloads(path):
    out = []
    for line in path.read_text().splitlines() if path.exists() else []:
        p = line.split("\t")
        if p and p[0] == "workload" and len(p) >= 5:
            out.append((p[1], p[2], p[3], p[4]))  # name, want, verdict, detail
    return out


def main():
    out = Path(sys.argv[1])
    why = {k: v[0] for k, v in load_host(out / "probes.tsv").items()}
    box = load_probe(out / "inside.tsv")
    host = load_host(out / "host.tsv")
    net_ids = [i for i in why if i.startswith("n.")]

    print("# plybox lab — step 2: loopback-only box + outside proxy\n")
    print("Network attack probes: `host` is no sandbox, `box` is inside plybox.\n")
    print("| probe | why it matters | host | box |")
    print("|---|---|---|---|")
    for i in net_ids:
        h = CELL.get(host.get(i, ("NA",))[0], "?")
        b = CELL.get(box.get(i, ("NA",))[0], "?")
        print(f"| `{i}` | {why[i]} | {h} | {b} |")

    opened = sum(1 for i in net_ids if box.get(i, ("NA",))[0] == "ALLOWED")
    print(f"\n**{opened} of {len(net_ids)} network doors open inside the box.**\n")

    print("## Workloads (is the box still usable, and shut where it must be?)\n")
    print("| workload | wanted | verdict | detail |")
    print("|---|---|---|---|")
    wl = load_workloads(out / "inside.tsv")
    for name, want, verdict, detail in wl:
        print(f"| {name} | {want} | {verdict} | {detail} |")
    fails = [w[0] for w in wl if w[2] != "pass"]
    if fails:
        print(f"\n**Workload FAILs: {', '.join(fails)}**")
    else:
        print(f"\n**All {len(wl)} workloads behaved as wanted.**")

    log = out / "proxy.jsonl"
    if log.exists():
        import json
        allowed = refused = 0
        refusals = []
        for line in log.read_text().splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("verdict") == "allowed":
                allowed += 1
            elif r.get("verdict") == "refused":
                refused += 1
                refusals.append(f"{r.get('host', r.get('target', '?'))}: {r.get('reason')}")
        print(f"\n## Proxy log\n\n{allowed} allowed, {refused} refused.\n")
        for r in refusals[:12]:
            print(f"- refused {r}")


if __name__ == "__main__":
    main()
