#!/usr/bin/env python3
"""plybox security suite report: the 41 probes and the workloads, both tiers.

    report.py <results-dir>
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


def with_hostside(rows, hostfile):
    for i, v in load_tsv(hostfile).items():
        if i in HOST_SIDE:
            rows[i] = v
    return rows


def main():
    out = Path(sys.argv[1])
    why = {k: v[0] for k, v in load_tsv(out / "probes.tsv").items()}
    order = list(why)
    data = {"host": load_tsv(out / "host.tsv")}
    data["plybox"] = with_hostside(load_tsv(out / "plybox.tsv", prefix="probe"), out / "plybox.host.tsv")
    if (out / "plybox.gvisor.tsv").exists():
        data["plybox --isolation gvisor"] = with_hostside(
            load_tsv(out / "plybox.gvisor.tsv", prefix="probe"), out / "plybox.gvisor.host.tsv")
    cols = list(data)

    def v(col, i):
        return data[col].get(i, ("NA",))[0]

    def opened(col, ids):
        if not data[col]:
            return "did not run"
        vs = [v(col, i) for i in ids]
        o, na = sum(x == "ALLOWED" for x in vs), sum(x == "NA" for x in vs)
        return f"{o} ({na} n/a)" if na else str(o)

    print("# plybox security suite: 41 attacker probes + workloads\n")
    print("`host` = no sandbox (the control). `plybox` = explicit `--isolation ns` tier, `plybox --isolation gvisor` = gVisor tier. "
          "Cells show open doors; `(n n/a)` = unmeasured, NOT closed.\n")
    print("## Open doors per class\n")
    print("| class | probes | " + " | ".join(cols) + " |")
    print("|---|---:|" + "---:|" * len(cols))
    for key, title in CLASSES.items():
        ids = [i for i in order if i.split(".")[0] == key]
        print(f"| {title} | {len(ids)} | " + " | ".join(opened(c, ids) for c in cols) + " |")
    print(f"| **Total** | {len(order)} | " + " | ".join(f"**{opened(c, order)}**" for c in cols) + " |")

    for col, stem in (("plybox", "plybox"), ("plybox --isolation gvisor", "plybox.gvisor")):
        if not (out / f"{stem}.tsv").exists():
            continue
        hostside = load_tsv(out / f"{stem}.host.tsv")
        if "s.env" in hostside or "s.leak" in hostside:
            print(f"\n## Secrets ({col})\n")
            print("| check | result | detail |")
            print("|---|---|---|")
            for i in ("s.env", "s.leak"):
                verdict, detail = hostside.get(i, ("NA", "not run"))
                print(f"| `{i}` | {CELL.get(verdict, '?')} | {detail} |")

        wl = load_workloads(out / f"{stem}.tsv")
        print(f"\n## Workloads ({col})\n")
        print("| workload | wanted | verdict | detail |")
        print("|---|---|---|---|")
        for name, want, verdict, detail in wl:
            print(f"| {name} | {want} | {verdict} | {detail} |")
        fails = [w[0] for w in wl if w[2] != "pass"]
        print(f"\n**{'FAILs: ' + ', '.join(fails) if fails else f'All {len(wl)} workloads behaved as wanted.'}**"
              if wl else "\n**No workload rows — the script did not run to completion.**")
        err = out / f"{stem}.err"
        if err.exists() and err.stat().st_size:
            lines = [l for l in err.read_text().splitlines() if l.strip()]
            if lines:
                print("\nstderr:\n")
                for l in lines[:10]:
                    print(f"    {l[:160]}")

    diff = out / "diff.txt"
    if diff.exists():
        lines = [l for l in diff.read_text().splitlines() if l.strip()]
        print(f"\n## `plybox diff` — what the box changed, held in the session ({len(lines)} entries)\n")
        for l in lines[:15]:
            print(f"    {l}")
        if len(lines) > 15:
            print(f"    … {len(lines) - 15} more")

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
        allowed = [r for r in net if r.get("verdict") == "allowed"]
        refused = [r for r in net if r.get("verdict") == "refused"]
        errors = [r for r in net if r.get("verdict") == "error"]
        terminated = [r for r in allowed if r.get("mode") == "terminated"]
        swapped = sum(r.get("secrets_substituted", 0) for r in allowed)
        print(f"\n## Session record\n\n{len(rows)} events: {len(allowed)} connections allowed "
              f"({len(terminated)} TLS-terminated for secrets, {swapped} substitutions), "
              f"{len(refused)} refused, {len(errors)} errors.\n")
        for r in refused[:6]:
            print(f"- refused {r.get('host', r.get('target', '?'))}: {r.get('reason')}")
        for r in errors[:6]:
            print(f"- **error** {r.get('host', '?')}: {r.get('reason')}")
        for col in [c for c in cols if c.startswith("plybox")]:
            still = [i for i in order if v(col, i) == "ALLOWED"]
            print(f"\n## Still open in {col}\n")
            print("\n".join(f"- `{i}` — {why[i]}: {data[col][i][1][:100]}" for i in still) if still else "Nothing measurable here.")


if __name__ == "__main__":
    main()
