#!/usr/bin/env bash
# plybox lab, step 5 (KVM half): boot the probe inside a Firecracker microVM.
#
#   vm/run.sh [runs]        default 5 boots; the last one's probe output is kept
#
# No root: /dev/kvm is world-accessible on this host. The guest is a 6.1
# kernel from Firecracker's CI bucket, a 64 MiB ext4 built with
# `mkfs.ext4 -d` (no mount, no root), and vminit as PID 1.
#
# What this measures: wall-clock from spawning the VMM to (a) the guest
# kernel handing over to init, (b) probe done, (c) VMM exit — and the 41
# probes as seen from INSIDE the guest. Read the latter carefully: inside a
# VM the "kernel doors" are doors into the GUEST kernel, which is the whole
# point — they are not doors into the host. The VM has no network here
# (tap devices need root), so the network probes are closed by absence.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
RUNS="${1:-5}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/vm-$STAMP"
RUN="$(mktemp -d "$LAB/.run.XXXXXX")"
mkdir -p "$OUT"
trap 'rm -rf "$RUN"' EXIT

TARGET="$(rustc -vV | sed -n 's/^host: //p')"
( cd "$LAB/probe"   && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --quiet --target "$TARGET" )
( cd "$LAB/vm/init" && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --quiet --target "$TARGET" )

# --- the guest disk: init + probe + empty mountpoints, no root needed ---
ROOT="$RUN/root"; mkdir -p "$ROOT"/{dev,proc,sys,tmp,work}
cp "$LAB/vm/init/target/$TARGET/release/vminit" "$ROOT/init"
cp "$LAB/probe/target/$TARGET/release/probe" "$ROOT/probe"
mkfs.ext4 -q -F -d "$ROOT" "$RUN/rootfs.ext4" 64M

cat > "$RUN/vm.json" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$LAB/tools/vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=0 init=/init"
  },
  "drives": [{ "drive_id": "rootfs", "path_on_host": "$RUN/rootfs.ext4",
               "is_root_device": true, "is_read_only": false }],
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 }
}
EOF

# One boot: stamp every serial line with host ms since the VMM was spawned.
boot() {
  local start; start=$(date +%s%N)
  "$LAB/tools/firecracker" --no-api --config-file "$RUN/vm.json" 2>&1 \
    | while IFS= read -r line; do
        printf '%d\t%s\n' $(( ($(date +%s%N) - start) / 1000000 )) "$line"
      done
  printf '%d\tvmm-exit\n' $(( ($(date +%s%N) - start) / 1000000 ))
}

echo "booting $RUNS times" >&2
for i in $(seq 1 "$RUNS"); do
  boot > "$OUT/boot-$i.log"
done

# Timing table from the markers.
{
  echo "# Firecracker microVM — start latency (host wall-clock ms from spawn)"
  echo
  echo "| boot | kernel→init | probe done | VMM exit | kernel's own boot time (guest ms) |"
  echo "|---:|---:|---:|---:|---:|"
  for i in $(seq 1 "$RUNS"); do
    f="$OUT/boot-$i.log"
    up=$(awk -F'\t' '$2=="vminit" && $3=="up"{print $1; exit}' "$f")
    gup=$(awk -F'\t' '$2=="vminit" && $3=="up"{print $4; exit}' "$f")
    done_=$(awk -F'\t' '$2=="vminit" && $3 ~ /^probe-/{print $1; exit}' "$f")
    exit_=$(awk -F'\t' '$2=="vmm-exit"{print $1; exit}' "$f")
    echo "| $i | ${up:-?} | ${done_:-?} | ${exit_:-?} | ${gup:-?} |"
  done
} > "$OUT/timing.md"

# Probe results from the last boot, in the lab's TSV shape.
awk -F'\t' 'NF>=3 && $2 ~ /^[kpfnq]\./ {print $2"\t"$3"\t"$4}' "$OUT/boot-$RUNS.log" > "$OUT/guest.tsv"
"$ROOT/probe" --list > "$OUT/probes.tsv"

cat "$OUT/timing.md"
echo
echo "probe rows captured from the guest: $(wc -l < "$OUT/guest.tsv")"
echo "results: $OUT" >&2
