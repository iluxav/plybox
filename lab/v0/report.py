#!/usr/bin/env python3
"""plybox lab: the binary vs the lab's bwrap+boxer reference.

    report.py <v0-results-dir>
"""
import json
import sys
from pathlib import Path

CELL = {"ALLOWED": "OPEN", "BLOCKED": "closed", "NA": "n/a"}
CLASSES = {"k": "Kernel attack surface", "p": "The process itself",
           "f": "Files, secrets, host IPC", "n": "Network", "q": "Resources"}
HOST_SIDE = {"f.inject.githook", "f.inject.agentcfg"}


def load_tsv(path, prefix=None):
    rows = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        p = line.split("\t")
        if prefix:
            if len(p) >= 3 and p[0] == prefix:
                rows[p[1]] = (p[2], p[3] if len(p) > 3 else "")
        elif len(p) >= 2:
            rows[p[0]] = (p[1], p[2] if len(p) > 2 else "")
    return rows


def load_workloads(path):
    out = []
    for line in path.read_text().splitlines() if path.exists() else []:
        p = line.split("\t")
        if p and p[0] == "workload" and len(p) >= 5:
            out.append((p[1], p[2], p[3], p[4]))
    return out


def latest(results, prefix):
    dirs = sorted(d for d in results.iterdir() if d.is_dir() and d.name.startswith(prefix))
    return dirs[-1] if dirs else None


def with_hostside(rows, hostfile):
    for i, v in load_tsv(hostfile).items():
        if i in HOST_SIDE:
            rows[i] = v
    return rows


def main():
    out = Path(sys.argv[1])
    results = out.parent
    why = {k: v[0] for k, v in load_tsv(out / "probes.tsv").items()}
    order = list(why)
    data = {"host": load_tsv(out / "host.tsv")}
    kern = latest(results, "kern-")
    if kern:
        data["lab box (bwrap+boxer)"] = with_hostside(load_tsv(kern / "box.boxer.tsv", prefix="probe"), kern / "box.boxer.host.tsv")
    data["plybox"] = with_hostside(load_tsv(out / "plybox.tsv", prefix="probe"), out / "plybox.host.tsv")
    cols = list(data)

    def v(col, i):
        return data[col].get(i, ("NA",))[0]

    def opened(col, ids):
        if not data[col]:
            return "did not run"
        vs = [v(col, i) for i in ids]
        o, na = sum(x == "ALLOWED" for x in vs), sum(x == "NA" for x in vs)
        return f"{o} ({na} n/a)" if na else str(o)

    print("# plybox v0 — slice 1 against the probes\n")
    print("`lab box` = the bwrap+boxer configuration the lab proved (step 3). `plybox` = the binary. "
          "They should match; any difference is a bug or a missing feature. "
          "Cells show open doors; `(n n/a)` = unmeasured, NOT closed.\n")
    print("## Open doors per class\n")
    print("| class | probes | " + " | ".join(cols) + " |")
    print("|---|---:|" + "---:|" * len(cols))
    for key, title in CLASSES.items():
        ids = [i for i in order if i.split(".")[0] == key]
        print(f"| {title} | {len(ids)} | " + " | ".join(opened(c, ids) for c in cols) + " |")
    print(f"| **Total** | {len(order)} | " + " | ".join(f"**{opened(c, order)}**" for c in cols) + " |")

    ref = "lab box (bwrap+boxer)"
    if ref in data and data[ref]:
        diffs = [i for i in order if v(ref, i) != v("plybox", i)]
        print("\n## Differences from the lab box\n")
        if diffs:
            print("| probe | lab box | plybox | plybox detail |")
            print("|---|---|---|---|")
            for i in diffs:
                print(f"| `{i}` | {CELL.get(v(ref, i), '?')} | {CELL.get(v('plybox', i), '?')} | {data['plybox'].get(i, ('', ''))[1][:100]} |")
        else:
            print("None — the binary reproduces the lab box exactly.")

    wl = load_workloads(out / "plybox.tsv")
    print("\n## Workloads under plybox\n")
    print("| workload | wanted | verdict | detail |")
    print("|---|---|---|---|")
    for name, want, verdict, detail in wl:
        print(f"| {name} | {want} | {verdict} | {detail} |")
    fails = [w[0] for w in wl if w[2] != "pass"]
    print(f"\n**{'FAILs: ' + ', '.join(fails) if fails else f'All {len(wl)} workloads behaved as wanted.'}**"
          if wl else "\n**No workload rows — the script did not run to completion.**")
    err = out / "plybox.err"
    if err.exists() and err.stat().st_size:
        lines = [l for l in err.read_text().splitlines() if l.strip()]
        if lines:
            print("\nstderr:\n")
            for l in lines[:10]:
                print(f"    {l[:160]}")

    lat = out / "latency.tsv"
    if lat.exists():
        print("\n## Start latency (median of 10, ms)\n")
        print("| what | ms |")
        print("|---|---:|")
        for line in lat.read_text().splitlines()[1:]:
            a, b = line.split("\t")
            print(f"| {a} | {b} |")

    rec = out / "record.jsonl"
    if rec.exists():
        rows = [json.loads(l) for l in rec.read_text().splitlines() if l.strip()]
        net = [r for r in rows if r.get("event") == "net"]
        allowed = sum(1 for r in net if r.get("verdict") == "allowed")
        refused = [r for r in net if r.get("verdict") == "refused"]
        print(f"\n## Session record\n\n{len(rows)} events: {allowed} connections allowed, {len(refused)} refused.\n")
        for r in refused[:6]:
            print(f"- refused {r.get('host', r.get('target', '?'))}: {r.get('reason')}")
        still = [i for i in order if v("plybox", i) == "ALLOWED"]
        print("\n## Still open in plybox (slice 1)\n")
        print("\n".join(f"- `{i}` — {why[i]}" for i in still) if still else "Nothing measurable here.")


if __name__ == "__main__":
    main()
