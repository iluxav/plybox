#!/usr/bin/env python3
"""Turn one results directory into a markdown matrix.

    matrix.py <results-dir> <config> [<config> ...]

Rows are probes, columns are configs. `host` (no sandbox) is the control:
a probe that is not ALLOWED on the host carries no signal on this machine,
and is listed separately.
"""
import sys
from pathlib import Path

CELL = {"ALLOWED": "OPEN", "BLOCKED": "closed", "NA": "n/a"}
CLASSES = {
    "k": "Kernel attack surface",
    "p": "The process itself",
    "f": "Files, secrets, host IPC",
    "n": "Network",
    "q": "Resources",
}


def load(path):
    rows = {}
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split("\t", 2)
            if len(parts) >= 2:
                rows[parts[0]] = (parts[1], parts[2] if len(parts) > 2 else "")
    return rows


def opened(rows, ids):
    """Open count for `ids`, with the unmeasured count beside it so a door the
    probe could not see is never mistaken for a closed one. A dash means the
    config never ran."""
    if not rows:
        return "–"
    verdicts = [rows.get(i, ("NA",))[0] for i in ids]
    open_ = sum(1 for v in verdicts if v == "ALLOWED")
    na = sum(1 for v in verdicts if v == "NA")
    return f"{open_} ({na} n/a)" if na else str(open_)


def main():
    out = Path(sys.argv[1])
    configs = sys.argv[2:]
    why = {k: v[0] for k, v in load(out / "probes.tsv").items()}
    order = list(why)
    data = {c: load(out / f"{c}.tsv") for c in configs}
    control = data.get("host", {})

    print(f"# plybox lab matrix\n\n{(out / 'machine.txt').read_text().strip()}\n")
    print("OPEN = the attacker step worked. closed = it failed. n/a = the probe could not tell — NOT the same as closed.\n")

    # summary: open doors per class, per config
    print("## Open doors per class\n")
    print("| class | probes | " + " | ".join(configs) + " |")
    print("|---|---:|" + "---:|" * len(configs))
    for key, title in CLASSES.items():
        ids = [i for i in order if i.split(".")[0] == key]
        cells = [opened(data[c], ids) for c in configs]
        print(f"| {title} | {len(ids)} | " + " | ".join(cells) + " |")
    totals = [opened(data[c], order) for c in configs]
    print(f"| **Total** | {len(order)} | " + " | ".join(f"**{t}**" for t in totals) + " |")

    # detail
    for key, title in CLASSES.items():
        print(f"\n## {title}\n")
        print("| probe | why it matters | " + " | ".join(configs) + " |")
        print("|---|---|" + "---|" * len(configs))
        for i in order:
            if i.split(".")[0] != key:
                continue
            cells = [CELL.get(data[c].get(i, ("NA",))[0], "?") if data[c] else "did not start" for c in configs]
            flag = "" if not control or control.get(i, ("NA",))[0] == "ALLOWED" else " *"
            print(f"| `{i}`{flag} | {why[i]} | " + " | ".join(cells) + " |")

    if control:
        quiet = [i for i in order if control.get(i, ("NA",))[0] != "ALLOWED"]
        if quiet:
            print("\n\\* Not open on the bare host, so this machine gives no signal for it:\n")
            for i in quiet:
                print(f"- `{i}`: {control.get(i, ('NA', 'not run'))[1]}")


if __name__ == "__main__":
    main()
