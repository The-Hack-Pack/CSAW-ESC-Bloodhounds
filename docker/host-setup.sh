#!/usr/bin/env bash
# Host-side settings the container cannot set for itself.
#
# Run once per boot on the Docker host (on macOS/Windows this means inside the
# Docker Desktop VM, not your laptop -- see the note at the bottom).
#
#   sudo bash docker/host-setup.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2; exit 1
fi

echo "== before =="
sysctl vm.mmap_rnd_bits kernel.core_pattern 2>/dev/null || true

# 1. ASLR entropy. Kernel 6.5+ defaults to 32 bits, which overlaps the region
#    ASan/TSan reserve for shadow memory. Symptom is a startup abort reading
#    "Shadow memory range interleaves with an existing memory mapping".
sysctl -w vm.mmap_rnd_bits=28

# 2. afl-fuzz refuses to start if crashes would be piped to a userspace
#    handler (apport, systemd-coredump), because it would miss them.
sysctl -w kernel.core_pattern=core

echo
echo "== after =="
sysctl vm.mmap_rnd_bits kernel.core_pattern

cat <<'EOF'

Not persistent across reboot. To make it stick:
  echo 'vm.mmap_rnd_bits=28'     | sudo tee /etc/sysctl.d/99-esc26.conf
  echo 'kernel.core_pattern=core' | sudo tee -a /etc/sysctl.d/99-esc26.conf

Docker Desktop (macOS / Windows): these are properties of the Linux VM, not
your host OS. Get a shell in the VM first:
  docker run --rm --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh
then run the two sysctl commands there.

Note that mmap_rnd_bits=28 slightly reduces ASLR entropy machine-wide. That is
fine for a disposable analysis box; do not do it on a machine you care about.
EOF
