#!/usr/bin/env python3
"""Exercise resume against real bubblewrap overlays in disposable directories.

Usage: python3 tests/sessions/resume.py /path/to/plybox
No network requests or real user sessions are used.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import fcntl

binary = str(Path(shutil.which(sys.argv[1] if len(sys.argv) > 1 else "plybox")).resolve())
root = Path(tempfile.mkdtemp(prefix="plybox-resume-lab."))
env = dict(os.environ, XDG_STATE_HOME=str(root / "state"))
base = root / "state/plybox/sessions"
work = root / "workspace"
work.mkdir()
checks = 0


def call(*args, ok=True, cwd=None, extra_env=None):
    p = subprocess.run([binary, *map(str, args)], cwd=cwd or root, env=env | (extra_env or {}),
                       capture_output=True, text=True, timeout=30)
    if ok:
        assert p.returncode == 0, f"{args}: exit {p.returncode}\n{p.stderr}\n{p.stdout}"
    else:
        assert p.returncode != 0, f"{args}: unexpectedly succeeded"
    return p


def checked(name, condition=True):
    global checks
    assert condition, name
    checks += 1
    print(f"pass  {name}", flush=True)


def metadata(name):
    return json.loads((base / name / "meta.json").read_text())


def start(name, command, *options):
    return call("run", "--isolation", "ns", "--quiet", "--session", base / name, "--work", work, *options,
                "--", "sh", "-c", command)


try:
    (work / "keep").write_text("host\n")
    (work / "deleted").write_text("host\n")
    start("saved-files", "echo first > keep; unlink deleted; echo new > added; echo once >> count",
          "--env", "LABEL=retained", "--allow", "example.com", "--pids", "128")
    original = metadata("saved-files")
    checked("initial run saved a pending overlay", (base / "saved-files/upper/added").is_file())

    # Resume the existing copy with a new command and the saved policy.
    call("run", "--resume", "saved-files", "--quiet", "--", "sh", "-c",
         'test "$LABEL" = retained && test ! -e deleted && test "$(cat keep)" = first '
         '&& test "$(cat added)" = new && echo twice >> count && echo second > keep')
    checked("resume sees additions, edits, deletions and saved environment")
    checked("original workspace remains untouched",
            (work / "keep").read_text() == "host\n" and (work / "deleted").exists() and not (work / "added").exists())
    saved = metadata("saved-files")
    checked("metadata retains initial start and counts both runs",
            saved["started_ns"] == original["started_ns"] and saved["runs"] == 2
            and saved["last_started_ns"] >= original["last_started_ns"] and saved["exit_code"] == 0
            and saved["ended"] is not None)
    checked("network rules and resource limits are retained",
            saved["policy"]["net"]["allow"] == ["example.com"] and saved["policy"]["limits"]["pids"] == 128)
    events = [json.loads(line) for line in (base / "saved-files/record.jsonl").read_text().splitlines()]
    starts = [e for e in events if e["event"] == "start"]
    checked("audit appends a second start and marks it resumed",
            len(starts) == 2 and not starts[0]["resumed"] and starts[1]["resumed"] and starts[1]["run"] == 2)

    call("--resume", "saved-files", "--quiet", "--", "sh", "-c", 'echo again >> count')
    call("--resume", "saved-f", "--quiet", cwd="/")
    checked("top-level shorthand and unique prefix repeat the saved command from another cwd",
            (base / "saved-files/upper/count").read_text() == "once\ntwice\nagain\nagain\n")
    start("newer-session", "true")
    call("--resume", "saved-files", "--quiet")
    call("run", "--resume", "--last", "--quiet", "--", "sh", "-c", "echo latest > latest")
    checked("--last follows the most recently resumed session", (base / "saved-files/upper/latest").exists())

    other = root / "other"
    other.mkdir()
    for options, message in [(["--work", other], "original workspace"),
                             (["--workspace-mode", "bind"], "overlay"),
                             (["--isolation", "gvisor"], "namespace"),
                             (["--session", base / "different"], "cannot be combined")]:
        p = call("run", "--resume", "saved-files", *options, "--", "true", ok=False)
        checked(f"invalid resume options refused: {options[0]}", message in p.stderr)
    before = (base / "saved-files/meta.json").read_bytes()
    call("run", "--session", base / "saved-files", "--work", work, "--", "true", ok=False)
    checked("--session cannot overwrite an existing run", before == (base / "saved-files/meta.json").read_bytes())

    # Missing isolation in saved state must retain its historical ns meaning,
    # independently of the defaults for a newly supplied policy.
    for missing in [("meta",), ("policy",), ("meta", "policy")]:
        legacy = metadata("saved-files")
        if "meta" in missing:
            legacy.pop("isolation")
        if "policy" in missing:
            legacy["policy"].pop("isolation")
            legacy["policy"]["fs"].pop("workspace_mode")
        (base / "saved-files/meta.json").write_text(json.dumps(legacy))
        call("--resume", "saved-files", "--quiet", "--", "sh", "-c", "test -f latest")
        saved = metadata("saved-files")
        checked(f"legacy missing isolation in {' and '.join(missing)} stays ns",
                saved["isolation"] == saved["policy"]["isolation"] == "ns"
                and saved["policy"]["fs"]["workspace_mode"] == "overlay")

    # Simulate metadata written by the old binary (no policy/isolation fields).
    legacy = dict(original)
    legacy.pop("policy")
    legacy.pop("isolation")
    (base / "saved-files/meta.json").write_text(json.dumps(legacy))
    p = call("--resume", "saved-files", "--", "true", ok=False)
    checked("legacy sessions require explicit policy instead of silently using defaults", "--policy" in p.stderr)
    policy = root / "legacy.toml"
    policy.write_text('isolation = "ns"\n[net]\nallow = ["example.com"]\n')
    call("--resume", "saved-files", "--policy", policy, "--quiet", "--", "sh", "-c", "test -f latest")
    call("--resume", "saved-files", "--quiet", cwd="/")
    checked("legacy session resumes with policy once, then uses saved policy")

    start("secret-session", "true", "--secret", "DUMMY_TOKEN=not-a-real-token@api.example.com",
          "--env", "DUMMY_TOKEN=not-a-real-token")
    text = (base / "secret-session/meta.json").read_text()
    checked("literal secret and matching environment value are not persisted", "not-a-real-token" not in text)
    call("--resume", "secret-session", "--quiet", ok=False, extra_env={"DUMMY_TOKEN": ""})
    call("--resume", "secret-session", "--quiet", extra_env={"DUMMY_TOKEN": "replacement-dummy-token"})
    checked("secret must be supplied again and is reloaded for the resumed run")
    token = root / "dummy-token"
    token.write_text("dummy-file-value\n")
    token.chmod(0o600)
    start("secret-file-session", "true", "--secret-file", "FILE_TOKEN=dummy-token@api.example.com")
    call("--resume", "secret-file-session", "--quiet", cwd="/")
    checked("relative secret file reference survives a different cwd",
            "dummy-file-value" not in (base / "secret-file-session/meta.json").read_text())
    token_link = root / "token-link"
    token_link.symlink_to(token.name)
    start("rotated-secret", "true", "--secret-file", "FILE_TOKEN=token-link@api.example.com")
    rotated = root / "new-token"
    rotated.write_text("rotated-dummy-value\n")
    rotated.chmod(0o600)
    token_link.unlink()
    token_link.symlink_to(rotated.name)
    token.unlink()
    call("--resume", "rotated-secret", "--quiet", cwd="/")
    checked("rotated secret symlink is read again instead of pinning the old file")

    # A real running resumed box: the supervisor's lock must protect against
    # every other operation, including prune of a currently empty session.
    start("locked-session", "true")
    proc = subprocess.Popen([binary, "--resume", "locked-session", "--quiet", "--", "sh", "-c",
                             "echo ready; sleep 4; echo pending > after-lock"],
                            cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        import select
        assert select.select([proc.stdout], [], [], 10)[0], "running box did not become ready"
        assert proc.stdout.readline().strip() == "ready", "running box failed"
        checked("sessions reports a running box", "running" in next(l for l in call("sessions").stdout.splitlines() if "locked-session" in l))
        with (base / "locked-session/lock").open("r+") as lock:
            try:
                fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                checked("bubblewrap holds its own lock independent of the supervisor")
            else:
                raise AssertionError("bubblewrap did not hold the runtime lock")
        for args in [("--resume", "locked-session"), ("apply", "locked-session"), ("discard", "locked-session")]:
            p = call(*args, ok=False)
            checked(f"concurrent {args[0]} refused", "in use" in p.stderr)
        call("sessions", "--prune")
        checked("prune leaves the running empty session alone", (base / "locked-session").is_dir() and proc.poll() is None)
        out, err = proc.communicate(timeout=10)
        assert proc.returncode == 0, err
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.communicate(timeout=10)
    call("--resume", "locked-session", "--quiet", "--", "sh", "-c", "test -f after-lock")
    checked("lock released after exit and saved changes are available")
    call("apply", "locked-session")
    p = call("--resume", "locked-session", ok=False)
    checked("applied session is not resumable", "already applied" in p.stderr)

    start("interrupted-session", "true")
    with (root / "interrupted.log").open("w") as log:
        proc = subprocess.Popen([binary, "--resume", "interrupted-session", "--quiet", "--pids", "128", "--", "sh", "-c",
                                 "echo ready; sleep 3; echo saved > after-interruption"],
                                cwd=root, env=env, stdout=subprocess.PIPE, stderr=log, text=True)
        try:
            assert select.select([proc.stdout], [], [], 10)[0], "interruption test did not become ready"
            assert proc.stdout.readline().strip() == "ready"
            proc.kill()
            proc.wait(timeout=10)
            # Depending on the limits engine, the sandbox dies with its parent
            # or briefly survives. Any survivor must still block operations.
            deadline = time.monotonic() + 10
            while True:
                line = next(l for l in call("sessions").stdout.splitlines() if "interrupted-session" in l)
                if "running" not in line:
                    break
                p = call("--resume", "interrupted-session", "--quiet", "--", "true", ok=False)
                assert "in use" in p.stderr
                assert time.monotonic() < deadline, "sandbox did not release runtime lock"
                time.sleep(0.05)
            call("--resume", "interrupted-session", "--quiet", "--", "true")
            checked("resume after supervisor death waits for the sandbox to release its lock")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
            proc.stdout.close()

    start("exit-session", "true")
    p = call("--resume", "exit-session", "--quiet", "--", "sh", "-c", "echo kept > failure; exit 7", ok=False)
    checked("failed workload exit status recorded and propagated", p.returncode == 7 and metadata("exit-session")["exit_code"] == 7)
    call("--resume", "exit-session", "--quiet", "--", "sh", "-c", "test -f failure")
    checked("failed command's files can be resumed")
    call("--resume", "exit-session", "--quiet", "--", "/missing-command", ok=False)
    call("--resume", "exit-session", "--quiet", "--", "true")
    checked("lock is released when command launch fails")

    start("bind-session", "true", "--workspace-mode", "bind")
    checked("bind session resume refused", "no saved workspace" in call("--resume", "bind-session", ok=False).stderr)
    start("broken-session", "true")
    (base / "broken-session/upper").rmdir()
    checked("missing upper layer refused", "upper directory" in call("--resume", "broken-session", ok=False).stderr)

    # HEAD warning is advisory; uncommitted edits are deliberately not claimed
    # to be detected. The lower directory is live, not a repository snapshot.
    git_env = env | {"GIT_AUTHOR_NAME": "Lab", "GIT_AUTHOR_EMAIL": "lab@example.test",
                     "GIT_COMMITTER_NAME": "Lab", "GIT_COMMITTER_EMAIL": "lab@example.test"}
    for args in [("init", "-q"), ("add", "."), ("commit", "-qm", "initial")]:
        subprocess.run(["git", "-C", str(work), *args], env=git_env, check=True, capture_output=True)
    start("changed-head", "true")
    subprocess.run(["git", "-C", str(work), "commit", "--allow-empty", "-qm", "next"], env=git_env, check=True, capture_output=True)
    p = call("--resume", "changed-head", "--quiet")
    checked("changed git HEAD produces a warning", "git HEAD changed" in p.stderr)

    # Apply the actual resumed overlay, verifying that deletion markers survived.
    call("apply", "saved-files")
    checked("apply carries all resumed edits and deletions",
            (work / "keep").read_text() == "second\n" and not (work / "deleted").exists()
            and (work / "added").read_text() == "new\n" and (work / "latest").read_text() == "latest\n")
    print(f"{checks} resume checks passed")
finally:
    print(f"lab directory: {root}")
