#!/usr/bin/env python3
"""Embedded runtime integrity, extraction, precedence and startup measurements."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import statistics
import subprocess
import sys
import tempfile
import time

binary = str(Path(sys.argv[1]).resolve())
root = Path(__file__).resolve().parents[2]
spec = json.loads((root / "third_party/gvisor/manifest.json").read_text())
payload_hash = hashlib.sha512((root / "third_party/gvisor/manifest.json").read_bytes()).hexdigest()
checks = 0


def checked(name, condition=True):
    global checks
    assert condition, name
    checks += 1
    print(f"PASS {name}", flush=True)


with tempfile.TemporaryDirectory(prefix="plybox-embedded.") as tmp:
    tmp = Path(tmp)
    # Only unshare is available to the launcher. Workload tools come from
    # /usr inside the box, as usual. The caller's state and runtime stay unused.
    bins = tmp / "bin"
    bins.mkdir()
    (bins / "unshare").symlink_to(shutil.which("unshare"))
    work = tmp / "work"
    work.mkdir()
    state = tmp / "state"
    env = {**os.environ, "PATH": str(bins), "XDG_STATE_HOME": str(state)}
    env.pop("PLYBOX_OPERATOR", None)
    cache = state / "plybox/runtimes" / payload_hash

    def run(name, *opts, ok=True, extra=None):
        session = tmp / f"session-{name}"
        p = subprocess.run([binary, "run", "--quiet", "--work", str(work), "--session", str(session),
                            *map(str, opts), "--", "sh", "-c", "echo embedded-ok"],
                           cwd=tmp, env=env | (extra or {}), capture_output=True, text=True, timeout=60)
        assert (p.returncode == 0) == ok, (name, p.returncode, p.stdout, p.stderr)
        if not ok:
            return p
        assert p.stdout == "embedded-ok\n", (name, p.stdout)
        return next(json.loads(line) for line in (session / "record.jsonl").read_text().splitlines()
                    if json.loads(line)["event"] == "start")["runsc"]

    def digest(path):
        with path.open("rb") as f:
            return hashlib.file_digest(f, "sha512").hexdigest()

    def replace(path, data):
        # runsc's gofer may still be exiting: replacing an inode is allowed
        # even while the old executable is busy (and matches cache repair).
        temporary = tmp / "tampered"
        temporary.write_bytes(data)
        temporary.chmod(0o500)
        temporary.replace(path)

    checked("version names the pinned embedded release",
            f"gVisor {spec['release']} (embedded)" in subprocess.check_output([binary, "version"], text=True))
    before = time.perf_counter()
    runtime = run("fresh")
    cold_ms = (time.perf_counter() - before) * 1000
    checked("fresh state with no external runsc runs the embedded default",
            runtime["source"] == "embedded" and runtime["path"] == str(cache / "runsc")
            and runtime["payload_sha512"] == payload_hash and runtime["release"] == spec["release"])
    checked("audit names the actual runsc checksum", runtime["sha512"] == digest(cache / "runsc"))
    checked("extracted directories are owner-only",
            all(stat.S_IMODE(p.stat().st_mode) == 0o700 for p in [cache.parent, cache, cache / "gvisor-bin"]))
    checked("every extracted executable has pinned contents and mode 0500",
            all(digest(cache / e["path"]) == e["sha512"] and stat.S_IMODE((cache / e["path"]).stat().st_mode) == 0o500
                for e in spec["files"]))
    checked("no unused checkpoint or metric binaries are extracted",
            sorted(str(p.relative_to(cache)) for p in cache.rglob("*") if p.is_file())
            == sorted([e["path"] for e in spec["files"]] + [".lock"]))

    marker = tmp / "must-not-execute"
    for index, entry in enumerate(spec["files"]):
        path = cache / entry["path"]
        # Same-size replacement tests the digest, not just length checks.
        data = f"#!/bin/sh\necho unsafe > {marker}\nexit 99\n".encode()
        replace(path, data + b"#" * (entry["size"] - len(data)))
        run(f"tamper-{index}")
        checked(f"tampered {entry['path']} is repaired before execution",
                not marker.exists() and digest(path) == entry["sha512"])
    target = cache / "runsc"
    replace(target, b"truncated")
    run("truncated")
    checked("truncated cached runsc is repaired", digest(target) == spec["files"][0]["sha512"])

    # Hostile filesystem entries are refused, never followed or chmodded.
    target.unlink()
    outside = tmp / "outside"
    outside.write_text("untouched")
    target.symlink_to(outside)
    p = run("symlink", ok=False)
    checked("cache symlink is refused without modifying its target",
            "embedded gVisor" in p.stderr and outside.read_text() == "untouched")
    target.unlink()
    os.mkfifo(target, 0o500)
    p = run("fifo", ok=False)
    checked("non-regular cache entry refuses promptly", "regular file" in p.stderr)
    target.unlink()
    run("restore")
    link = tmp / "hard-link"
    os.link(target, link)
    checked("hard-linked cache file is refused", "hard links" in run("hardlink", ok=False).stderr)
    link.unlink()
    cache.chmod(0o777)
    checked("unsafe cache directory permissions are refused", "0700" in run("directory-mode", ok=False).stderr)
    cache.chmod(0o700)

    # A PATH runtime must never win over an embedded payload, nor rescue a
    # corrupt/unsafe cache. Explicit choices must win without touching cache.
    fake = bins / "runsc"
    fake.write_text(f"#!/bin/sh\necho unsafe > {marker}\nexit 99\n")
    fake.chmod(0o700)
    run("path-ignored")
    checked("PATH runtime cannot override embedded runtime", not marker.exists())
    cache.chmod(0o777)
    run("no-fallback", ok=False)
    checked("unsafe cache cannot fall back to PATH", not marker.exists())
    # Copy the known-good external fixture to a path with spaces. Its helpers
    # remain a directory link, to exercise explicit-runtime compatibility.
    external_dir = tmp / "external runtime"
    external_dir.mkdir()
    external = external_dir / "runsc"
    shutil.copy2(root / "tests/tools/runsc", external)
    (external_dir / "gvisor-bin").symlink_to(root / "tests/tools/gvisor-bin")
    r = run("explicit", "--runsc", external)
    checked("--runsc overrides embedding even with an unsafe cache",
            r["source"] == "configured" and r["path"] == str(external) and r["sha512"] == digest(external))
    policy = tmp / "policy.toml"
    policy.write_text(f'runsc = "{external}"\n')
    checked("policy runsc overrides embedding", run("policy", "--policy", policy)["path"] == str(external))
    policy.write_text(f'runsc = "{tmp / "missing"}"\n')
    checked("--runsc overrides the policy runtime",
            run("cli-over-policy", "--policy", policy, "--runsc", external)["path"] == str(external))
    operator = tmp / "operator.toml"
    operator.write_text(f'host_rootfs = true\npaths = ["{work}"]\nsessions = "{tmp}"\nrunsc = "{external}"\n')
    checked("operator runsc overrides embedding",
            run("operator", extra={"PLYBOX_OPERATOR": str(operator)})["path"] == str(external))
    p = run("missing-explicit", "--runsc", tmp / "missing", ok=False)
    checked("missing explicit runsc never falls back to embedded", "runsc not found" in p.stderr)
    cache.chmod(0o700)

    # Environment variables understood by upstream cannot bypass validation.
    r = run("hostile-env", extra={"GVISOR_SIDECAR_BINARIES_DIR": str(bins), "GVISOR_ENFORCE_RELEASE": "wrong-release"})
    checked("embedded launch pins sidecar directory and release despite inherited env", r["source"] == "embedded")
    r = run("hostile-env-limits", "--pids", "128", "--mem", "512M",
            extra={"PATH": os.environ["PATH"], "GVISOR_SIDECAR_BINARIES_DIR": str(bins),
                   "GVISOR_ENFORCE_RELEASE": "wrong-release"})
    checked("limits wrapper preserves verified runtime environment", r["source"] == "embedded")

    # Each process makes a distinct session, sharing only the new runtime cache.
    concurrent_state = tmp / "concurrent-state"
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda n: run(f"concurrent-{n}", extra={"XDG_STATE_HOME": str(concurrent_state)}), range(4)))
    checked("four concurrent first launches all succeed using one cache",
            len({r["path"] for r in results}) == 1)
    checked("concurrent extraction leaves no partial files", not list(concurrent_state.rglob("*.tmp")))

    inode = target.stat().st_ino
    verification_ms = []
    warm_ms = []
    for n in range(20):
        before = time.perf_counter()
        r = run(f"warm-{n}")
        warm_ms.append((time.perf_counter() - before) * 1000)
        verification_ms.append(r["verification_us"] / 1000)
    checked("warm starts reuse the verified file without rewriting it", inode == target.stat().st_ino)
    print(f"TIMING first launch {cold_ms:.2f} ms; warm launch median {statistics.median(warm_ms):.2f} ms; "
          f"SHA-512 verification median {statistics.median(verification_ms):.2f} ms "
          f"(range {min(verification_ms):.2f}–{max(verification_ms):.2f}, n=20)", flush=True)

print(f"{checks} embedded-runtime checks passed")
