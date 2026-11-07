#!/usr/bin/env python3
"""Fetch the pinned runtime, verify upstream SHA512SUMS, then select our payload.

Already verified files need no network. The same committed manifest is checked
again by build.rs, so editing downloaded executables cannot change the bundle.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

root = Path(__file__).resolve().parents[1]
spec = json.loads((root / "third_party/gvisor/manifest.json").read_text())
dest = root / "tests/tools"


def matches(entry):
    path = dest / entry["path"]
    if not path.is_file() or path.stat().st_size != entry["size"]:
        return False
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha512").hexdigest() == entry["sha512"]


if all(matches(entry) for entry in spec["files"]):
    print(f"gVisor {spec['release']}: verified cached payload")
else:
    with tempfile.TemporaryDirectory(prefix=".fetch-", dir=dest) as tmp:
        tmp = Path(tmp)
        url = f"https://github.com/google/gvisor/releases/download/{spec['release']}"
        for name in ["SHA512SUMS", spec["archive"]]:
            subprocess.run(["curl", "-fL", "--retry", "2", "-o", str(tmp / name), f"{url}/{name}"], check=True)
        sums = {row.split()[1].lstrip("*"): row.split()[0] for row in (tmp / "SHA512SUMS").read_text().splitlines()}
        assert sums[spec["archive"]] == spec["archive_sha512"], "upstream archive checksum changed from the committed pin"
        archive = tmp / spec["archive"]
        with archive.open("rb") as f:
            assert hashlib.file_digest(f, "sha512").hexdigest() == spec["archive_sha512"], "gVisor archive checksum mismatch"
        with tarfile.open(archive) as tar:
            for entry in spec["files"]:
                member = tar.getmember(entry["path"])
                assert member.isfile() and member.size == entry["size"], entry["path"]
                data = tar.extractfile(member).read()
                assert hashlib.sha512(data).hexdigest() == entry["sha512"], entry["path"]
                path = dest / entry["path"]
                path.parent.mkdir(exist_ok=True)
                temporary = tmp / path.name
                temporary.write_bytes(data)
                temporary.chmod(0o755)
                os.replace(temporary, path)
        print(f"gVisor {spec['release']}: downloaded and verified payload")
