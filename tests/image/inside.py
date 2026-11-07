"""plybox lab, images: network workloads in Python (slim images have no curl).

Prints `workload <TAB> name <TAB> wanted <TAB> verdict <TAB> detail`, the same
shape as net/inside.sh, so the reports read both.
"""
import socket
import time
import urllib.request


def wl(name, want, fn):
    t0 = time.monotonic()
    try:
        detail = fn()
        got = "ok"
    except Exception as e:  # a refused/failed step is the measurement
        detail = f"{type(e).__name__}: {e}"[:80]
        got = "blocked"
    ms = int((time.monotonic() - t0) * 1000)
    verdict = "pass" if got == want else "FAIL"
    print(f"workload\t{name}\t{want}\t{verdict}\t{ms}ms {detail}", flush=True)


wl("https allowed host", "ok", lambda: f"status {urllib.request.urlopen('https://pypi.org/simple/six/', timeout=20).status}")
wl("https denied host", "blocked", lambda: f"status {urllib.request.urlopen('https://example.com/', timeout=15).status}")


def direct():
    s = socket.create_connection(("1.1.1.1", 443), timeout=5)
    s.close()
    return "connected"


wl("direct tcp (no proxy)", "blocked", direct)
