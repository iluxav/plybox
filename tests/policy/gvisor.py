#!/usr/bin/env python3
"""gVisor workspace/identity regressions, using only disposable local files.

    gvisor.py PLYBOX RUNSC [--image IMAGE]
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("plybox")
parser.add_argument("runsc")
parser.add_argument("--image")
args = parser.parse_args()
binary = str(Path(args.plybox).resolve())
runsc = str(Path(args.runsc).resolve())

with tempfile.TemporaryDirectory(prefix="pgtest.") as tmp:
    root = Path(tmp)
    work = root / "work"
    work.mkdir(mode=0o755)
    private = work / "private"
    private.mkdir(mode=0o700)
    original = private / "existing"
    original.write_text("before")
    original.chmod(0o600)
    readonly = root / "readonly"
    readonly.mkdir(mode=0o700)
    (readonly / "file").write_text("readable")
    (readonly / "file").chmod(0o600)
    original_stat = original.stat()
    work_stat = work.stat()
    env = {**os.environ, "XDG_STATE_HOME": str(root / "state")}
    number = 0

    def run(code, mode="bind", *options):
        global number
        number += 1
        command = [binary, "run", "--quiet", "--isolation", "gvisor", "--runsc", runsc,
                   "--session", str(root / f"session-{number}"), "--work", str(work),
                   "--workspace-mode", mode, "--ro-bind", f"{readonly}:/opt/readonly"]
        if args.image:
            command += ["--image", args.image]
        result = subprocess.run(command + list(options) + ["--", "python3", "-c", code],
                                env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
        session = root / f"session-{number}"
        for path in [session, session / "sock"]:
            assert stat.S_IMODE(path.stat().st_mode) == 0o700, path
        return result.stdout

    identity = json.loads(run('''
import json, os
from pathlib import Path
work = Path('/work')
original = work / 'private/existing'
assert original.read_text() == 'before'
original.write_text('after')
(work / 'newdir').mkdir()
(work / 'newdir/result.json').write_text('{"ok":true}')
(work / 'newdir/result.json').rename(work / 'result.json')
(work / 'newdir').rmdir()
(work / 'deleted').write_text('remove me')
(work / 'deleted').unlink()
status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
assert all(int(status[name], 16) == 0 for name in ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])
assert int(status['NoNewPrivs']) == 1
assert int(status['Seccomp']) == 2
assert Path('/opt/readonly/file').read_text() == 'readable'
try:
    Path('/opt/readonly/file').write_text('changed')
except PermissionError:
    pass
except OSError as e:
    import errno
    assert e.errno == errno.EROFS, e
else:
    raise AssertionError('ro_bind became writable in bind mode')
print(json.dumps([os.getuid(), os.getgid(), work.stat().st_uid, work.stat().st_gid]))
'''))
    assert identity == [os.getuid(), os.getgid(), work_stat.st_uid, work_stat.st_gid], identity
    assert original.read_text() == "after"
    assert json.loads((work / "result.json").read_text()) == {"ok": True}
    assert not (work / "deleted").exists() and not (work / "newdir").exists()
    for path, before in [(work, work_stat), (original, original_stat)]:
        after = path.stat()
        assert (after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) == (
            before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode))
    assert (work / "result.json").stat().st_uid == os.getuid()
    print("PASS gVisor bind creates, edits, renames and deletes as the caller; permissions unchanged", flush=True)
    print("PASS gVisor workload has no capabilities, no_new_privs and seccomp", flush=True)

    # A new invocation can read the private files written by the last one.
    work.chmod(0o700)
    run("from pathlib import Path; assert Path('/work/private/existing').read_text() == 'after'")
    print("PASS gVisor can reuse an owner-only workspace", flush=True)

    run('''
import errno, os
from pathlib import Path
assert Path('/work/private/existing').read_text() == 'after'
assert Path('/opt/readonly/file').read_text() == 'readable'
for path in ['/work/new', '/work/private/existing', '/opt/readonly/file', '/opt/readonly/new']:
    try:
        with open(path, 'w') as f: f.write('changed')
    except OSError as e:
        assert e.errno in (errno.EROFS, errno.EACCES), e
    else:
        raise AssertionError('write succeeded: ' + path)
for directory in ['/tmp', os.environ['HOME']]:
    Path(directory, 'scratch').write_text('ok')
''', "overlay")
    assert original.read_text() == "after" and not (work / "new").exists()
    assert (readonly / "file").read_text() == "readable" and not (readonly / "new").exists()
    print("PASS gVisor overlay workspace and ro_bind stay read-only; scratch stays writable", flush=True)

    run(r'''
import socket, stat
from pathlib import Path
assert stat.S_IMODE(Path('/run/plybox/sock/proxy.sock').stat().st_mode) == 0o600
with socket.create_connection(('127.0.0.1', 3128), timeout=5) as connection:
    connection.sendall(b'CONNECT denied.invalid:443 HTTP/1.1\r\nHost: denied.invalid:443\r\n\r\n')
    response = connection.recv(1024)
    assert b'403' in response.split(b'\r\n', 1)[0], response
''')
    print("PASS gVisor reaches the proxy and denied destinations stay blocked", flush=True)

    # This would fail if the ownership fix changed the workload to UID 0:
    # root is exempt from RLIMIT_NPROC. Bound both the attempts and lifetime.
    if os.getuid() != 0:
        run('''
import errno, os, resource, signal
assert os.getuid() != 0
assert resource.getrlimit(resource.RLIMIT_NPROC) == (128, 128)
children = []
limited = False
try:
    for _ in range(160):
        try: pid = os.fork()
        except OSError as e:
            assert e.errno == errno.EAGAIN, e
            limited = True
            break
        if pid == 0:
            signal.alarm(10)
            signal.pause()
            os._exit(0)
        children.append(pid)
finally:
    for pid in children: os.kill(pid, signal.SIGKILL)
    for pid in children: os.waitpid(pid, 0)
assert limited and 0 < len(children) < 128, len(children)
''', "bind", "--pids", "128", "--mem", "512M")
        print("PASS gVisor process limit still stops a bounded fork test", flush=True)
    else:
        print("SKIP non-root process-limit check: run this suite as an ordinary user", flush=True)
