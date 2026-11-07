#!/usr/bin/env python3
"""plybox lab, images: report for image/run.sh.

    report.py <image-results-dir>
"""
import sys
from pathlib import Path

CELL = {"ALLOWED": "OPEN", "BLOCKED": "closed", "NA": "n/a"}
CLASSES = {"k": "Kernel attack surface", "p": "The process itself",
           "f": "Files, secrets, host IPC", "n": "Network", "q": "Resources"}
HOST_SIDE = {"f.inject.githook", "f.inject.agentcfg"}


def load(path, prefix=None):
    rows = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        p = line.split("\t")
        if prefix:
            if len(p) >= 3 and p[0] == prefix:
                rows[p[1]] = (p[2], p[3] if len(p) > 3 else "")
        elif len(p) >= 2:
            rows[p[0]] = (p[1], p[2] if len(p) > 2 else "")
    return rows


def workloads(path):
    out = []
    for line in path.read_text().splitlines() if path.exists() else []:
        p = line.split("\t")
        if p and p[0] == "workload" and len(p) >= 5:
            out.append(p[1:5])
    return out


def main():
    out = Path(sys.argv[1])
    image = (out / "image.txt").read_text().strip() if (out / "image.txt").exists() else "?"
    why = {k: v[0] for k, v in load(out / "probes.tsv").items()}
    order = list(why)
    data = {"host": load(out / "host.tsv")}
    for col in ("image.ns", "image.gvisor"):
        if (out / f"{col}.tsv").exists():
            rows = load(out / f"{col}.tsv", prefix="probe")
            for i, v in load(out / f"{col}.host.tsv").items():
                if i in HOST_SIDE:
                    rows[i] = v
            data[col] = rows
    cols = list(data)

    def v(c, i):
        return data[c].get(i, ("NA",))[0]

    def opened(c, ids):
        vs = [v(c, i) for i in ids]
        o, na = sum(x == "ALLOWED" for x in vs), sum(x == "NA" for x in vs)
        return f"{o} ({na} n/a)" if na else str(o)

    print(f"# plybox lab — the 41 probes inside an image: `{image}`\n")
    print("Cells show open doors; `(n n/a)` = unmeasured, NOT closed.\n")
    print("| class | probes | " + " | ".join(cols) + " |")
    print("|---|---:|" + "---:|" * len(cols))
    for key, title in CLASSES.items():
        ids = [i for i in order if i.split(".")[0] == key]
        print(f"| {title} | {len(ids)} | " + " | ".join(opened(c, ids) for c in cols) + " |")
    print(f"| **Total** | {len(order)} | " + " | ".join(f"**{opened(c, order)}**" for c in cols) + " |")

    for c in cols[1:]:
        still = [i for i in order if v(c, i) == "ALLOWED"]
        print(f"\n## Still open in {c}\n")
        print("\n".join(f"- `{i}` — {why[i]}: {data[c][i][1][:100]}" for i in still) if still else "Nothing measurable here.")
        wl = workloads(out / f"{c}.tsv")
        print(f"\n### Workloads ({c})\n")
        print("| workload | wanted | verdict | detail |")
        print("|---|---|---|---|")
        for row in wl:
            print("| " + " | ".join(row) + " |")
        fails = [w[0] for w in wl if w[2] != "pass"]
        print(f"\n**{'FAILs: ' + ', '.join(fails) if fails else f'All {len(wl)} workloads behaved as wanted.'}**"
              if wl else "\n**No workload rows.**")
        err = out / f"{c}.err"
        if err.exists():
            lines = [l for l in err.read_text().splitlines() if l.strip() and "landlock" not in l]
            if lines:
                print("\nstderr:\n")
                for l in lines[:8]:
                    print(f"    {l[:160]}")

    lat = out / "latency.tsv"
    if lat.exists():
        print("\n## Start latency (median of 10, ms)\n")
        print("| what | ms |")
        print("|---|---:|")
        for line in lat.read_text().splitlines()[1:]:
            a, b = line.split("\t")
            print(f"| {a} | {b} |")


if __name__ == "__main__":
    main()
