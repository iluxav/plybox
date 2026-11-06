#!/usr/bin/env python3
"""plybox lab step 5 report: kernel tiers side by side.

    report.py <gv-results-dir>

Columns: host, box.full (latest step-4 run), gv (gVisor alone), gv.box
(gVisor + proxy + boxer + limits), vm (latest Firecracker run, guest view).
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


def main():
    out = Path(sys.argv[1])
    results = out.parent
    why = {k: v[0] for k, v in load_tsv(out / "probes.tsv").items()}
    order = list(why)

    data = {"host": load_tsv(out / "host.tsv")}
    full = latest(results, "full-")
    if full:
        data["box.full"] = load_tsv(full / "box.full.tsv", prefix="probe")
        for i, v in load_tsv(full / "box.full.host.tsv").items():
            if i in HOST_SIDE:
                data["box.full"][i] = v
    for col in ("gv", "gv.box"):
        data[col] = load_tsv(out / f"{col}.tsv", prefix="probe")
        for i, v in load_tsv(out / f"{col}.host.tsv").items():
            if i in HOST_SIDE:
                data[col][i] = v
    vm = latest(results, "vm-")
    if vm:
        data["vm (guest view)"] = load_tsv(vm / "guest.tsv")
    cols = list(data)

    def v(col, i):
        return data[col].get(i, ("NA",))[0]

    def opened(col, ids):
        vs = [v(col, i) for i in ids]
        o, na = sum(x == "ALLOWED" for x in vs), sum(x == "NA" for x in vs)
        return f"{o} ({na} n/a)" if na else str(o)

    print("# plybox lab — step 5: a second kernel\n")
    print("`host` = no sandbox. `box.full` = step 4 (namespaces + proxy + boxer + overlay + secrets + limits). "
          "`gv` = gVisor alone. `gv.box` = gVisor + proxy + boxer + limits. "
          "`vm (guest view)` = the probe run as root INSIDE a Firecracker microVM: its kernel doors lead "
          "into the GUEST kernel, not the host — the VM boundary is what protects the host, and the probe "
          "cannot see it. Cells show open doors; `(n n/a)` = unmeasured, NOT closed.\n")

    print("## Open doors per class\n")
    print("| class | probes | " + " | ".join(cols) + " |")
    print("|---|---:|" + "---:|" * len(cols))
    for key, title in CLASSES.items():
        ids = [i for i in order if i.split(".")[0] == key]
        print(f"| {title} | {len(ids)} | " + " | ".join(opened(c, ids) for c in cols) + " |")
    print(f"| **Total** | {len(order)} | " + " | ".join(f"**{opened(c, order)}**" for c in cols) + " |")

    print("\n## Kernel doors by tier\n")
    print("| probe | why it matters | " + " | ".join(cols) + " |")
    print("|---|---|" + "---|" * len(cols))
    for i in order:
        if i.startswith("k.") or i == "p.seccomp":
            print(f"| `{i}` | {why[i]} | " + " | ".join(CELL.get(v(c, i), "?") for c in cols) + " |")

    print("\n## How gVisor closes a door (gv column details)\n")
    for i in order:
        if i.startswith("k.") and v("gv", i) == "BLOCKED":
            print(f"- `{i}`: {data['gv'][i][1]}")

    wl = load_workloads(out / "gv.box.tsv")
    print("\n## Workloads under gVisor + proxy + boxer (gv.box)\n")
    print("| workload | wanted | verdict | detail |")
    print("|---|---|---|---|")
    for name, want, verdict, detail in wl:
        print(f"| {name} | {want} | {verdict} | {detail} |")
    fails = [w[0] for w in wl if w[2] != "pass"]
    print(f"\n**{'Workload FAILs: ' + ', '.join(fails) if fails else f'All {len(wl)} workloads behaved as wanted.'}**")
    err = out / "gv.box.err"
    if err.exists() and err.stat().st_size:
        lines = [l for l in err.read_text().splitlines() if "socat" not in l]
        if lines:
            print("\nstderr from gv.box:\n")
            for l in lines[:8]:
                print(f"    {l}")

    lat = out / "latency.tsv"
    if lat.exists():
        print("\n## Start latency (median of 10, ms from spawn to `/bin/true` exiting)\n")
        print("| tier | ms |")
        print("|---|---:|")
        for line in lat.read_text().splitlines()[1:]:
            tier, ms = line.split("\t")
            print(f"| {tier} | {ms} |")

    still = [i for i in order if v("gv.box", i) == "ALLOWED"]
    print("\n## Still open in gv.box\n")
    print("\n".join(f"- `{i}` — {why[i]}: {data['gv.box'][i][1]}" for i in still) if still else "Nothing measurable here.")

    log = out / "proxy.jsonl"
    if log.exists():
        rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
        n = {k: sum(1 for r in rows if r.get("verdict") == k) for k in ("allowed", "refused", "error")}
        print(f"\n## Proxy log\n\n{n['allowed']} allowed, {n['refused']} refused, {n['error']} errors.")
        for r in [r for r in rows if r.get("verdict") == "error"][:5]:
            print(f"- **error** {r.get('host')}: {r.get('reason')}")


if __name__ == "__main__":
    main()
