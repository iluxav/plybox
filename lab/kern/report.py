#!/usr/bin/env python3
"""plybox lab step 3 report: kernel surface across host / box.net / box.boxer.

    report.py <results-dir>
"""
import json
import sys
from pathlib import Path

CELL = {"ALLOWED": "OPEN", "BLOCKED": "closed", "NA": "n/a"}
CLASSES = {"k": "Kernel attack surface", "p": "The process itself",
           "f": "Files, secrets, host IPC", "n": "Network", "q": "Resources"}
COLS = ["host", "box.net", "box.boxer"]


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
            out.append((p[1], p[2], p[3], p[4]))
    return out


def main():
    out = Path(sys.argv[1])
    why = {k: v[0] for k, v in load_host(out / "probes.tsv").items()}
    order = list(why)
    data = {
        "host": load_host(out / "host.tsv"),
        "box.net": load_probe(out / "box.net.tsv"),
        "box.boxer": load_probe(out / "box.boxer.tsv"),
    }

    def v(col, i):
        return data[col].get(i, ("NA",))[0]

    print("# plybox lab — step 3: seccomp allowlist + Landlock (boxer)\n")
    print("`host` = no sandbox. `box.net` = step 2 (namespaces + loopback + proxy). "
          "`box.boxer` = box.net with the workload wrapped in boxer.\n")

    print("## Open doors per class\n")
    print("| class | probes | " + " | ".join(COLS) + " |")
    print("|---|---:|" + "---:|" * len(COLS))
    for key, title in CLASSES.items():
        ids = [i for i in order if i.split(".")[0] == key]
        cells = [str(sum(1 for i in ids if v(c, i) == "ALLOWED")) for c in COLS]
        print(f"| {title} | {len(ids)} | " + " | ".join(cells) + " |")
    tot = [str(sum(1 for i in order if v(c, i) == "ALLOWED")) for c in COLS]
    print(f"| **Total** | {len(order)} | " + " | ".join(f"**{t}**" for t in tot) + " |")

    # The headline: the 8 kernel doors step 1 left open with no network.
    print("\n## Kernel doors (the step-3 target)\n")
    print("| probe | why it matters | " + " | ".join(COLS) + " |")
    print("|---|---|" + "---|" * len(COLS))
    for i in order:
        if not (i.startswith("k.") or i == "p.seccomp"):
            continue
        cells = [CELL.get(v(c, i), "?") for c in COLS]
        print(f"| `{i}` | {why[i]} | " + " | ".join(cells) + " |")

    # Did boxer break the box?
    wl = load_workloads(out / "box.boxer.tsv")
    print("\n## Workloads under boxer\n")
    print("| workload | wanted | verdict | detail |")
    print("|---|---|---|---|")
    for name, want, verdict, detail in wl:
        print(f"| {name} | {want} | {verdict} | {detail} |")
    fails = [w[0] for w in wl if w[2] != "pass"]
    print(f"\n**{'Workload FAILs: ' + ', '.join(fails) if fails else f'All {len(wl)} workloads behaved as wanted.'}**")

    # Anything still ALLOWED in box.boxer, for the honest ledger.
    still = [i for i in order if v("box.boxer", i) == "ALLOWED"]
    if still:
        print("\n## Still open in box.boxer (next steps)\n")
        for i in still:
            print(f"- `{i}` — {why[i]}: {data['box.boxer'].get(i, ('', ''))[1]}")


if __name__ == "__main__":
    main()
