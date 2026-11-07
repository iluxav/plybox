#!/usr/bin/env python3
"""Default tier, explicit namespace opt-in, and fail-closed option checks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1]).resolve())
runsc = Path(sys.argv[2]).resolve()
checks = 0
embedded = "(embedded)" in subprocess.check_output([binary, "version"], text=True)


def checked(name, condition=True):
    global checks
    assert condition, name
    checks += 1
    print(f"PASS {name}", flush=True)


with tempfile.TemporaryDirectory(prefix="plybox-defaults.") as tmp:
    root = Path(tmp)
    work = root / "work"
    work.mkdir()
    base = root / "state/plybox/sessions"
    base.mkdir(parents=True)
    env = {**os.environ, "XDG_STATE_HOME": str(root / "state"),
           "PATH": f"{runsc.parent}:{os.environ['PATH']}"}

    def call(*args, ok=True, extra_env=None):
        p = subprocess.run([binary, *map(str, args)], env=env | (extra_env or {}),
                           cwd=root, capture_output=True, text=True, timeout=30)
        assert (p.returncode == 0) == ok, (args, p.returncode, p.stdout, p.stderr)
        return p

    def start(name, *opts, command="true", ok=True, extra_env=None):
        return call("run", "--quiet", "--work", work, "--session", base / name,
                    *opts, "--", "sh", "-c", command, ok=ok, extra_env=extra_env)

    def meta(name):
        return json.loads((base / name / "meta.json").read_text())

    def events(name):
        return [json.loads(line) for line in (base / name / "record.jsonl").read_text().splitlines()]

    # No isolation flag or policy: use the default runtime and record the
    # actual read-only mount, never a fictitious persistent overlay.
    start("default", command='echo scratch > /tmp/default; ! touch /work/must-not-write')
    m = meta("default")
    event = next(e for e in events("default") if e["event"] == "start")
    checked("plain run defaults to gVisor with a read-only workspace",
            m["isolation"] == event["isolation"] == m["policy"]["isolation"] == "gvisor"
            and event["runsc"]["source"] == ("embedded" if embedded else "PATH")
            and m["workspace_mode"] == event["workspace_mode"] == "readonly"
            and not (work / "must-not-write").exists() and not (base / "default/upper").exists())
    checked("gVisor session listing says it has no copy", "no copy (gvisor)" in call("sessions").stdout)
    for action in ["diff", "apply", "--resume"]:
        p = call(action, "default", ok=False)
        checked(f"gVisor {action} refuses with namespace guidance", "--isolation ns" in p.stderr)
    # Older gVisor records used the overlay label despite having no upper.
    m["workspace_mode"] = "overlay"
    (base / "default/meta.json").write_text(json.dumps(m))
    checked("old gVisor overlay label cannot make diff/apply usable",
            "--isolation ns" in call("apply", "default", ok=False).stderr
            and "--isolation ns" in call("diff", "default", ok=False).stderr)
    call("discard", "default")
    checked("gVisor audit-only sessions can be discarded", not (base / "default").exists())

    policy = root / "policy.toml"
    policy.write_text("[env]\nLABEL = 'policy'\n")
    start("policy-default", "--policy", policy, command='test "$LABEL" = policy')
    checked("policy without isolation uses gVisor", meta("policy-default")["isolation"] == "gvisor")
    call("sessions", "--prune")
    checked("prune removes finished gVisor audit-only sessions", not (base / "policy-default").exists())

    # A fake bwrap on an otherwise empty PATH detects any attempted fallback.
    fake = root / "bin"
    fake.mkdir()
    marker = root / "fallback-ran"
    (fake / "bwrap").write_text(f"#!/bin/sh\necho ran > {marker}\nexit 99\n")
    (fake / "bwrap").chmod(0o755)
    (fake / "unshare").symlink_to("/usr/bin/unshare")
    for name, opts in [("missing-path", []), ("missing-configured", ["--runsc", root / "missing-runsc"])]:
        if name == "missing-path" and embedded:
            start(name, extra_env={"PATH": str(fake)})
            checked("no runsc on PATH: embedded runtime runs without bwrap",
                    not marker.exists() and next(e for e in events(name) if e["event"] == "start")["runsc"]["source"] == "embedded")
            continue
        p = start(name, *opts, ok=False, extra_env={"PATH": str(fake)})
        checked(f"{name}: missing runsc never falls back to bwrap",
                "runsc not found" in p.stderr and "make tools" in p.stderr
                and "gvisor.dev" in p.stderr and "--isolation ns" in p.stderr
                and not marker.exists() and not any(e["event"] == "start" for e in events(name)))

    for name, opts in [("tmpfs", ["--tmpfs", "3M"]), ("disk", ["--disk", "16M"]),
                       ("overlay", ["--workspace-mode", "overlay"])]:
        p = start(name, *opts, ok=False)
        checked(f"default gVisor refuses {name} before creating a session",
                "--isolation ns" in p.stderr and not (base / name).exists())
    policy.write_text("[fs]\nworkspace_mode = 'overlay'\n")
    p = start("policy-overlay", "--policy", policy, ok=False)
    checked("TOML overlay also requires explicit namespace opt-in", "--isolation ns" in p.stderr)

    policy.write_text("isolation = 'ns'\n")
    start("ns-policy", "--policy", policy, command="echo staged > result")
    checked("explicit ns policy preserves overlay staging",
            meta("ns-policy")["workspace_mode"] == "overlay"
            and (base / "ns-policy/upper/result").read_text() == "staged\n"
            and not (work / "result").exists())
    start("ns-flag", "--isolation", "ns", command="echo staged > result")
    checked("explicit ns flag preserves overlay staging", meta("ns-flag")["isolation"] == "ns")
    start("bind", "--workspace-mode", "bind", command="echo direct > result")
    checked("gVisor bind writes directly when explicitly requested", (work / "result").read_text() == "direct\n")

    operator = root / "operator.toml"
    common = f"host_rootfs = true\npaths = ['{work}']\nsessions = '{base}'\n"
    operator.write_text(common)
    op_env = {"PLYBOX_OPERATOR": str(operator)}
    start("operator-default", extra_env=op_env)
    checked("operator without forced isolation retains new default", meta("operator-default")["isolation"] == "gvisor")
    operator.write_text("isolation = 'ns'\n" + common)
    start("operator-ns", "--tmpfs", "3M", extra_env=op_env)
    checked("operator ns override wins before storage and workspace validation",
            meta("operator-ns")["isolation"] == "ns" and meta("operator-ns")["workspace_mode"] == "overlay")
    operator.write_text("isolation = 'gvisor'\n" + common)
    start("operator-gvisor", "--isolation", "ns", extra_env=op_env)
    checked("operator gVisor override wins over explicit ns",
            meta("operator-gvisor")["isolation"] == "gvisor" and meta("operator-gvisor")["workspace_mode"] == "readonly")
    p = start("operator-caps", "--isolation", "ns", "--tmpfs", "3M", ok=False, extra_env=op_env)
    checked("operator gVisor override cannot run namespace storage caps", "--isolation ns" in p.stderr)

print(f"{checks} default-tier checks passed")
