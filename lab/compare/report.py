#!/usr/bin/env python3
"""plybox lab comparison report: ours vs srt vs greywall, same probes.

    report.py <compare-results-dir>
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
    full = latest(results, "full-")
    if full:
        data["ours (box.full)"] = with_hostside(load_tsv(full / "box.full.tsv", prefix="probe"), full / "box.full.host.tsv")
    gv = latest(results, "gv-")
    if gv:
        data["ours (gv.box)"] = with_hostside(load_tsv(gv / "gv.box.tsv", prefix="probe"), gv / "gv.box.host.tsv")
    for col in ("srt", "greywall"):
        data[col] = with_hostside(load_tsv(out / f"{col}.tsv", prefix="probe"), out / f"{col}.host.tsv")
    cols = list(data)

    def v(col, i):
        return data[col].get(i, ("NA",))[0]

    def opened(col, ids):
        if not data[col]:
            return "did not run"
        vs = [v(col, i) for i in ids]
        o, na = sum(x == "ALLOWED" for x in vs), sum(x == "NA" for x in vs)
        return f"{o} ({na} n/a)" if na else str(o)

    print("# plybox lab — comparison: the same 41 doors, other sandboxes\n")
    print("Each tool runs with its own defaults plus the same allow list "
          "(api.anthropic.com, *.anthropic.com, registry.npmjs.org). `srt` = Anthropic sandbox-runtime. "
          "`greywall` = Greywall + greyproxy (global deny rule + the allows). "
          "Cells show open doors; `(n n/a)` = unmeasured, NOT closed. "
          "For the two planted-file probes the cell is the HOST-side truth (did the file land?).\n")

    print("## Open doors per class\n")
    print("| class | probes | " + " | ".join(cols) + " |")
    print("|---|---:|" + "---:|" * len(cols))
    for key, title in CLASSES.items():
        ids = [i for i in order if i.split(".")[0] == key]
        print(f"| {title} | {len(ids)} | " + " | ".join(opened(c, ids) for c in cols) + " |")
    print(f"| **Total** | {len(order)} | " + " | ".join(f"**{opened(c, order)}**" for c in cols) + " |")

    print("\n## Every door, every tool\n")
    print("| probe | why it matters | " + " | ".join(cols) + " |")
    print("|---|---|" + "---|" * len(cols))
    for i in order:
        if v("host", i) != "ALLOWED":
            continue  # no signal on this machine
        print(f"| `{i}` | {why[i]} | " + " | ".join(CELL.get(v(c, i), "?") for c in cols) + " |")
    print("\n(Rows not open on the bare host are omitted: this machine gives no signal for them.)")

    for col in ("srt", "greywall"):
        print(f"\n## Doors {col} leaves open that ours closes\n")
        ours = "ours (box.full)"
        diff = [i for i in order if v(col, i) == "ALLOWED" and ours in data and v(ours, i) != "ALLOWED"]
        if diff:
            for i in diff:
                print(f"- `{i}` — {why[i]}: {data[col][i][1][:110]}")
        else:
            print("None.")
        rev = [i for i in order if ours in data and v(ours, i) == "ALLOWED" and v(col, i) != "ALLOWED"]
        if rev:
            print(f"\nAnd the reverse — closed by {col}, open in ours:\n")
            for i in rev:
                print(f"- `{i}`")

        wl = load_workloads(out / f"{col}.tsv")
        print(f"\n### Workloads under {col}\n")
        print("| workload | wanted | verdict | detail |")
        print("|---|---|---|---|")
        for name, want, verdict, detail in wl:
            print(f"| {name} | {want} | {verdict} | {detail} |")
        fails = [w[0] for w in wl if w[2] != "pass"]
        print(f"\n**{'FAILs: ' + ', '.join(fails) if fails else f'All {len(wl)} workloads behaved as wanted.'}**"
              if wl else "\n**No workload rows — the tool did not run the script to completion.**")
        err = out / f"{col}.err"
        if err.exists() and err.stat().st_size:
            lines = [l for l in err.read_text().splitlines() if l.strip() and "socat" not in l]
            if lines:
                print(f"\nstderr from {col} (first lines):\n")
                for l in lines[:10]:
                    print(f"    {l[:160]}")

    lat = out / "latency.tsv"
    if lat.exists():
        print("\n## Start latency (median of 10, ms from spawn to `/bin/true` exiting)\n")
        print("| tool | ms |")
        print("|---|---:|")
        for line in lat.read_text().splitlines()[1:]:
            tier, ms = line.split("\t")
            print(f"| {tier} | {ms} |")

    glog = out / "greyproxy.logs.json"
    if glog.exists() and glog.stat().st_size:
        try:
            logs = json.loads(glog.read_text())
            items = logs if isinstance(logs, list) else logs.get("logs") or logs.get("items") or []
            print(f"\n## greyproxy connection log\n\n{len(items)} decisions recorded; first few:\n")
            for r in items[:8]:
                print(f"- {json.dumps(r)[:200]}")
        except ValueError:
            pass


if __name__ == "__main__":
    main()
