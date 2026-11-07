#!/usr/bin/env python3
"""Local, warm, whole-box measurements. Requires a working systemd user manager."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
TIERS = ["host", "ns", "gvisor"]
CASES = ["agent-tunnel", "agent-secret", "stream-tunnel", "stream-secret",
         "download-tunnel", "upload-tunnel", "download-secret", "upload-secret",
         "service", "cpu", "files", "idle", "idle10"]
TOKEN = "plybox-benchmark-only-key"


def output(argv):
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT).strip()


def line(process, timeout):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise TimeoutError(f"worker did not respond within {timeout}s")
    text = process.stdout.readline()
    if not text:
        raise RuntimeError(f"worker closed stdout (exit {process.poll()})")
    return json.loads(text)


def counter(cgroup):
    return int(dict(row.split() for row in (cgroup / "cpu.stat").read_text().splitlines())["usage_usec"])


def snapshot(cgroup):
    pids = set()
    for path in [cgroup / "cgroup.procs", *cgroup.glob("**/cgroup.procs")]:
        try:
            pids.update(map(int, path.read_text().split()))
        except FileNotFoundError:
            pass
    processes = []
    for pid in sorted(pids):
        base = Path(f"/proc/{pid}")
        try:
            command = (base / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            entry = {"pid": pid, "command": command}
            try:
                fields = {}
                for row in (base / "smaps_rollup").read_text().splitlines():
                    name, *values = row.split()
                    if name in ["Rss:", "Pss:"]:
                        fields[name[:-1].lower() + "_bytes"] = int(values[0]) * 1024
                entry.update(fields)
            except PermissionError:
                entry["smaps_error"] = "permission denied"
            processes.append(entry)
        except (FileNotFoundError, ProcessLookupError):
            pass
    result = {"memory_current_bytes": int((cgroup / "memory.current").read_text()),
              "memory_peak_bytes": int((cgroup / "memory.peak").read_text()), "processes": processes}
    for field in ["rss_bytes", "pss_bytes"]:
        result[field] = sum(p[field] for p in processes) if processes and all(field in p for p in processes) else None
    result["memory_stat"] = dict((k, int(v)) for k, v in
                                 (row.split() for row in (cgroup / "memory.stat").read_text().splitlines()))
    return result


class Invocation:
    def __init__(self, runner, tier, case, repeat, index=0):
        self.runner = runner
        self.tier = tier
        self.case = case
        self.unit = f"plybox-bench-{uuid.uuid4().hex}.scope"
        self.name = f"{case}-{tier}-{repeat}-{index}"
        self.session = runner.tmp / self.name
        self.log = open(runner.out / f"{self.name}.stderr", "w")
        self.process = None
        self.cgroup = None
        a = runner.args
        env = runner.env.copy()
        if case.startswith("idle"):
            # The shell execs sleep, leaving no Python measurement helper in
            # the box. Its only purpose is the startup barrier on stdin.
            command = ["/bin/sh", "-c", "printf '{\"ready\":true}\\n'; read go; exec /bin/sleep 3600"]
        else:
            script = str(runner.work / "workload.py") if tier == "host" else "/work/workload.py"
            ca = str(runner.work / "ca.pem") if tier == "host" else "/work/ca.pem"
            command = ["/usr/bin/python3", "-B", script, case, "--port", str(runner.port), "--ca", ca,
                       "--requests", str(a.requests), "--transfer-bytes",
                       str(a.secret_upload_bytes if case == "upload-secret" else a.transfer_bytes),
                       "--service-requests", str(a.service_requests), "--cpu-iterations", str(a.cpu_iterations),
                       "--file-iterations", str(a.file_iterations)]
            if tier != "host":
                command.append("--proxy")
            if case.endswith("-secret"):
                command.append("--secret")
        if tier == "host":
            env["BENCH_TOKEN"] = TOKEN
        else:
            box = [str(a.binary), "run", "--quiet", "--work", str(runner.work), "--session", str(self.session)]
            if tier == "ns":
                box += ["--isolation", "ns"]
            # gvisor intentionally has no isolation/runsc flag: exercise the
            # embedded default, and verify its selection in the audit record.
            if case.startswith(("agent-", "stream-", "download-", "upload-")):
                box += ["--allow", "fixture.test", "--map", f"fixture.test=127.0.0.1:{runner.port}"]
                if case.endswith("-secret"):
                    box += ["--trust-ca", str(runner.ca / "ca.pem"), "--secret", f"BENCH_TOKEN={TOKEN}@fixture.test"]
            command = box + ["--", *command]
        argv = ["systemd-run", "--user", "--scope", "--quiet", f"--unit={self.unit}",
                "--property=MemoryAccounting=yes", "--", *command]
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=self.log, text=True, env=env, cwd=runner.work)
            self.ready = line(self.process, 120)
            assert self.ready["ready"], self.ready
            relative = output(["systemctl", "--user", "show", self.unit, "--property=ControlGroup", "--value"])
            assert relative.startswith("/") and relative != "/", relative
            self.cgroup = Path("/sys/fs/cgroup") / relative.lstrip("/")
            counter(self.cgroup)
            self.before = snapshot(self.cgroup)
            if tier != "host":
                rows = [json.loads(s) for s in (self.session / "record.jsonl").read_text().splitlines()]
                self.start = next(r for r in rows if r["event"] == "start")
                if tier == "gvisor":
                    assert self.start["runsc"]["source"] == "embedded", self.start
                    # All launcher/gofer/sentry tasks must remain in this
                    # accounting scope, including daemons reparented to init.
                    commands = [p["command"] for p in self.before["processes"]]
                    assert any("runsc-sandbox" in c or "gvisor_sentry" in c for c in commands), commands
                    assert any("gofer" in c for c in commands), commands
        except BaseException:
            self.close(force=True)
            raise

    def send(self, text):
        self.process.stdin.write(text + "\n")
        self.process.stdin.flush()

    def close(self, force=False):
        if self.process is not None:
            if force or self.case.startswith("idle"):
                subprocess.run(["systemctl", "--user", "kill", "--signal=SIGKILL", self.unit],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                self.send("EXIT")
            try:
                code = self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                subprocess.run(["systemctl", "--user", "kill", "--signal=SIGKILL", self.unit],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.process.kill()
                self.process.wait(timeout=10)
                raise
            finally:
                self.log.close()
            if not force and not self.case.startswith("idle"):
                assert code == 0, (self.name, code, "see stderr file")
        else:
            self.log.close()

    def audit(self):
        if self.tier == "host":
            return None
        rows = [json.loads(s) for s in (self.session / "record.jsonl").read_text().splitlines()]
        net = [r for r in rows if r["event"] == "net"]
        assert not [r for r in rows if r.get("event") == "error" or r.get("verdict") == "error"], rows[-3:]
        if self.case.startswith(("agent-", "stream-", "download-", "upload-")):
            expected = self.runner.args.requests + 20 if self.case.startswith(("agent-", "stream-")) else 2
            assert len(net) == expected, (self.name, len(net), expected)
            mode = "terminated" if self.case.endswith("-secret") else "tunnel"
            assert all(r["mode"] == mode and r["verdict"] == "allowed" for r in net), net[:2]
            if mode == "terminated":
                assert all(r["secrets_substituted"] >= 1 for r in net), net[:2]
        return {"runsc": self.start["runsc"], "limits": self.start["limits"],
                "connections": len(net), "net_modes": sorted({r.get("mode") for r in net})}


class Runner:
    def __init__(self, args, tmp, out):
        self.args, self.tmp, self.out = args, tmp, out
        self.work, self.ca = tmp / "work", tmp / "ca"
        self.work.mkdir()
        shutil.copy2(HERE / "workload.py", self.work / "workload.py")
        subprocess.run([sys.executable, str(ROOT / "tests/helpers/proxy.py"), "mkcert", "--ca-dir",
                        str(self.ca), "--host", "fixture.test"], check=True, capture_output=True)
        shutil.copy2(self.ca / "ca.pem", self.work / "ca.pem")
        self.env = os.environ.copy()
        for key in ["PLYBOX_OPERATOR", "SSL_CERT_FILE", "SSL_CERT_DIR", "PYTHONPATH", "PYTHONHOME",
                    "GVISOR_SIDECAR_BINARIES_DIR", "GVISOR_ENFORCE_RELEASE"]:
            self.env.pop(key, None)
        self.env["XDG_STATE_HOME"] = str(tmp / "state")
        self.env["PYTHONHASHSEED"] = "0"
        self.fixture_log = open(out / "fixture.stderr", "w")
        self.fixture = subprocess.Popen([sys.executable, str(HERE / "fixture.py"), "--cert",
                                         str(self.ca / "fixture.test.pem"), "--key", str(self.ca / "fixture.test.key")],
                                        stdout=subprocess.PIPE, stderr=self.fixture_log, text=True)
        info = line(self.fixture, 10)
        self.port = info["port"]
        self.fixture_info = info

    def active(self, tier, case, repeat):
        run = Invocation(self, tier, case, repeat)
        try:
            cpu_before = counter(run.cgroup)
            run.send("GO")
            result = line(run.process, 600)
            cpu_after = counter(run.cgroup)
            assert result.pop("done"), result
            after = snapshot(run.cgroup)
            result["cpu_seconds"] = (cpu_after - cpu_before) / 1e6
            if "bytes" in result:
                result["cpu_seconds_GB"] = result["cpu_seconds"] / (result["bytes"] / 1e9)
            if "requests" in result:
                result["cpu_ms_request"] = result["cpu_seconds"] / result["requests"] * 1000
            run.close()
            return {"metrics": result, "ready": run.ready, "before": run.before, "after": after, "audit": run.audit()}
        except BaseException:
            run.close(force=True)
            raise

    def idle(self, tier, case, repeat):
        runs = []
        count = 10 if case == "idle10" else 1
        duration = self.args.multi_idle_seconds if count == 10 else self.args.idle_seconds
        try:
            for i in range(count):
                run = Invocation(self, tier, case, repeat, i)
                runs.append(run)
                run.send("GO")
            # Wait for sh to exec sleep and for transient runtime startup to
            # settle before collecting CPU or steady-state memory.
            time.sleep(2)
            cpu_before = sum(counter(r.cgroup) for r in runs)
            start = time.monotonic()
            samples = []
            for n in range(6):
                deadline = start + duration * n / 5
                time.sleep(max(0, deadline - time.monotonic()))
                samples.append([snapshot(r.cgroup) for r in runs])
            elapsed = time.monotonic() - start
            cpu_after = sum(counter(r.cgroup) for r in runs)
            metrics = {"seconds": elapsed, "boxes": count, "cpu_seconds": (cpu_after - cpu_before) / 1e6}
            for field in ["rss_bytes", "pss_bytes", "memory_current_bytes", "memory_peak_bytes"]:
                totals = [sum(s[field] for s in sample) if all(s[field] is not None for s in sample) else None
                          for sample in samples]
                metrics[field] = statistics.median(totals) if all(v is not None for v in totals) else None
            return {"metrics": metrics, "samples": samples,
                    "accounting": "sum of independent whole-box cgroups; memory median of six snapshots"}
        finally:
            for run in runs:
                run.close(force=True)

    def close(self):
        self.fixture.terminate()
        self.fixture.wait(timeout=10)
        self.fixture_log.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--cases", default=",".join(CASES))
    ap.add_argument("--tiers", default=",".join(TIERS))
    ap.add_argument("--requests", type=int, default=500)
    ap.add_argument("--transfer-bytes", type=int, default=200_000_000)
    ap.add_argument("--secret-upload-bytes", type=int, default=32_000_000,
                    help="below the terminated proxy's intentional 64 MiB request cap")
    ap.add_argument("--service-requests", type=int, default=10000)
    ap.add_argument("--cpu-iterations", type=int, default=100000)
    ap.add_argument("--file-iterations", type=int, default=20000)
    ap.add_argument("--idle-seconds", type=float, default=60)
    ap.add_argument("--multi-idle-seconds", type=float, default=10)
    args = ap.parse_args()
    args.binary = args.binary.resolve()
    cases, tiers = args.cases.split(","), args.tiers.split(",")
    assert set(cases) <= set(CASES) and set(tiers) <= set(TIERS)
    assert args.repeats > 0 and args.idle_seconds > 0 and args.multi_idle_seconds > 0
    version = output([str(args.binary), "version"])
    assert "(embedded)" in version, "make build first: benchmark requires the embedded release build"
    # Fail before running any workloads if whole-tree cgroup accounting is
    # unavailable. Do not silently substitute workload-only getrusage.
    output(["systemd-run", "--user", "--scope", "--quiet", "/bin/true"])
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = (args.output or ROOT / "tests/results" / f"bench-{stamp}").resolve()
    out.mkdir(parents=True, exist_ok=False)
    metadata = {"utc": stamp, "commit": output(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
                "binary_sha512": hashlib.file_digest(args.binary.open("rb"), "sha512").hexdigest(),
                "version": version, "platform": "systrap (runsc default; no platform override)",
                "kernel": platform.uname()._asdict(), "lscpu": json.loads(output(["lscpu", "-J"])),
                "meminfo": Path("/proc/meminfo").read_text(), "affinity": sorted(os.sched_getaffinity(0)),
                "python": output(["/usr/bin/python3", "--version"]), "openssl": output(["openssl", "version"]),
                "bwrap": output(["bwrap", "--version"]), "tmp_fs": output(["stat", "-f", "-c", "%T", "/tmp"]),
                "systemd": output(["systemd-run", "--version"]),
                "governors": sorted({p.read_text().strip() for p in Path("/sys/devices/system/cpu").glob("cpu*/cpufreq/scaling_governor")}),
                "harness_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.glob("*.py")},
                "args": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                "accounting": "cgroup v2 cpu.stat usage_usec delta between workload barriers; upstream excluded"}
    (out / "machine.json").write_text(json.dumps(metadata, indent=2) + "\n")
    began = time.monotonic()
    print(f"results: {out}", flush=True)
    with tempfile.TemporaryDirectory(prefix=".run.bench-", dir=ROOT / "tests") as tmp:
        runner = Runner(args, Path(tmp), out)
        metadata["fixture"] = runner.fixture_info
        try:
            with (out / "raw.jsonl").open("w") as raw:
                for case in cases:
                    for repeat in range(args.repeats):
                        # Rotate order to avoid always giving one tier the
                        # cold CPU, busiest desktop or last place in a batch.
                        order = tiers[repeat % len(tiers):] + tiers[:repeat % len(tiers)]
                        for tier in order:
                            print(f"start {case} {tier} trial {repeat + 1}/{args.repeats}", flush=True)
                            data = (runner.idle if case.startswith("idle") else runner.active)(tier, case, repeat)
                            row = {"case": case, "tier": tier, "repeat": repeat + 1, **data}
                            raw.write(json.dumps(row) + "\n")
                            raw.flush()
                            print("done " + json.dumps({"case": case, "tier": tier, **data["metrics"]}), flush=True)
        finally:
            runner.close()
    metadata["elapsed_seconds"] = time.monotonic() - began
    (out / "machine.json").write_text(json.dumps(metadata, indent=2) + "\n")
    subprocess.run([sys.executable, str(HERE / "report.py"), str(out)], check=True)


if __name__ == "__main__":
    main()
