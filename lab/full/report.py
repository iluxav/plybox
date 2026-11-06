#!/usr/bin/env python3
"""plybox lab step 4 report: the whole box, host / box.boxer / box.full.

    report.py <results-dir>

For the two planted-file probes the box column shows the HOST-side truth
(did the file land in the real workspace?), since that is where the threat
is; the inside view is in the detail.
"""
import json
import sys
from pathlib import Path

CELL = {"ALLOWED": "OPEN", "BLOCKED": "closed", "NA": "n/a"}
CLASSES = {"k": "Kernel attack surface", "p": "The process itself",
           "f": "Files, secrets, host IPC", "n": "Network", "q": "Resources"}
COLS = ["host", "box.boxer", "box.full"]
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


def main():
    out = Path(sys.argv[1])
    why = {k: v[0] for k, v in load_tsv(out / "probes.tsv").items()}
    order = list(why)
    data = {"host": load_tsv(out / "host.tsv")}
    hostside = {}
    for col in ("box.boxer", "box.full"):
        data[col] = load_tsv(out / f"{col}.tsv", prefix="probe")
        hostside[col] = load_tsv(out / f"{col}.host.tsv")
        for i in HOST_SIDE:
            if i in hostside[col]:
                data[col][i] = hostside[col][i]

    def v(col, i):
        return data[col].get(i, ("NA",))[0]

    def opened(col, ids):
        vs = [v(col, i) for i in ids]
        o, na = sum(x == "ALLOWED" for x in vs), sum(x == "NA" for x in vs)
        return f"{o} ({na} n/a)" if na else str(o)

    print("# plybox lab — step 4: the whole box\n")
    print("`host` = no sandbox. `box.boxer` = step 3. `box.full` = step 3 + workspace overlay "
          "+ secrets kept outside + cgroup limits. No root anywhere. "
          "Cells show open doors; `(n n/a)` = doors the probe could not measure, which are NOT closed.\n")

    print("## Open doors per class\n")
    print("| class | probes | " + " | ".join(COLS) + " |")
    print("|---|---:|" + "---:|" * len(COLS))
    for key, title in CLASSES.items():
        ids = [i for i in order if i.split(".")[0] == key]
        print(f"| {title} | {len(ids)} | " + " | ".join(opened(c, ids) for c in COLS) + " |")
    print(f"| **Total** | {len(order)} | " + " | ".join(f"**{opened(c, order)}**" for c in COLS) + " |")

    print("\n## The step-4 targets\n")
    print("| probe | why it matters | " + " | ".join(COLS) + " |")
    print("|---|---|" + "---|" * len(COLS))
    for i in order:
        if i in HOST_SIDE or i.startswith("q."):
            cells = [CELL.get(v(c, i), "?") for c in COLS]
            tag = " (host-side)" if i in HOST_SIDE else ""
            print(f"| `{i}`{tag} | {why[i]} | " + " | ".join(cells) + " |")
    for i in sorted(HOST_SIDE | {"q.pids", "q.mem"}):
        print(f"- `{i}` in box.full: {data['box.full'].get(i, ('NA', 'not run'))[1]}")

    print("\n## Secrets (box.full)\n")
    print("| check | result | detail |")
    print("|---|---|---|")
    for i in ("s.env", "s.leak"):
        verdict, detail = hostside["box.full"].get(i, ("NA", "not run"))
        print(f"| `{i}` | {CELL.get(verdict, '?')} | {detail} |")
    wl = load_workloads(out / "box.full.tsv")
    print("\n## Workloads (box.full)\n")
    print("| workload | wanted | verdict | detail |")
    print("|---|---|---|---|")
    for name, want, verdict, detail in wl:
        print(f"| {name} | {want} | {verdict} | {detail} |")
    fails = [w[0] for w in wl if w[2] != "pass"]
    print(f"\n**{'Workload FAILs: ' + ', '.join(fails) if fails else f'All {len(wl)} workloads behaved as wanted.'}**")

    upper = out / "box.full.upper.txt"
    if upper.exists():
        files = [l for l in upper.read_text().splitlines() if l]
        print(f"\n## What the box wrote (the overlay's upper layer — `plybox diff`)\n\n{len(files)} entries:\n")
        for f in files[:20]:
            print(f"- `{f}`")
        if len(files) > 20:
            print(f"- … {len(files) - 20} more")

    log = out / "proxy.jsonl"
    if log.exists():
        rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        allowed = [r for r in rows if r.get("verdict") == "allowed"]
        refused = [r for r in rows if r.get("verdict") == "refused"]
        errors = [r for r in rows if r.get("verdict") == "error"]
        terminated = [r for r in allowed if r.get("mode") == "terminated"]
        swapped = sum(r.get("secrets_substituted", 0) for r in allowed)
        print(f"\n## Proxy log\n\n{len(allowed)} allowed ({len(terminated)} TLS-terminated for secrets, "
              f"{swapped} substitutions), {len(refused)} refused, {len(errors)} errors.\n")
        for r in refused[:10]:
            print(f"- refused {r.get('host', r.get('target', '?'))}: {r.get('reason')}")
        for r in errors[:10]:
            print(f"- **error** {r.get('host', '?')}: {r.get('reason')}")

    still = [i for i in order if v("box.full", i) == "ALLOWED"]
    print("\n## Still open in box.full\n")
    if still:
        for i in still:
            print(f"- `{i}` — {why[i]}: {data['box.full'][i][1]}")
    else:
        print("Nothing. Every door that was open on the host and measurable here is closed.")


if __name__ == "__main__":
    main()
