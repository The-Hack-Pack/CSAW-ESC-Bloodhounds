#!/usr/bin/env bash
# Preflight. The failure modes below are silent and waste hours: a container
# where the sanitizers cannot map shadow memory just reports "no bugs found",
# which is indistinguishable from a working run that found nothing.
set -euo pipefail

fail=0

# 1. ASLR entropy. Kernels 6.5+ default vm.mmap_rnd_bits=32, which collides
#    with the ASan/TSan shadow mapping. This is a HOST sysctl -- it cannot be
#    fixed from inside the container. See docker/host-setup.sh.
if [ -r /proc/sys/vm/mmap_rnd_bits ]; then
    bits=$(cat /proc/sys/vm/mmap_rnd_bits)
    if [ "$bits" -gt 28 ]; then
        echo "FATAL: vm.mmap_rnd_bits=$bits (need <=28)." >&2
        echo "       Sanitizers will fail to map shadow memory." >&2
        echo "       On the HOST run: sudo sysctl -w vm.mmap_rnd_bits=28" >&2
        fail=1
    fi
fi

# 2. seccomp. Sanitizers call personality() to disable ASLR; the default
#    Docker seccomp profile blocks it.
if ! (cd /tmp && printf 'int main(){return 0;}' > _p.c \
      && gcc -fsanitize=address _p.c -o _p 2>/dev/null && ./_p 2>/dev/null); then
    echo "FATAL: ASan smoke test failed." >&2
    echo "       Run the container with: --security-opt seccomp=unconfined" >&2
    fail=1
fi
rm -f /tmp/_p /tmp/_p.c

# 3. CPU count. The planted race is paced with sleeps so it reproduces on a
#    single core, but real concurrency bugs need real parallelism.
cpus=$(nproc)
if [ "$cpus" -lt 2 ]; then
    echo "WARN: only $cpus CPU visible. Planted bugs still reproduce, but" >&2
    echo "      genuine race hunting needs --cpus 4 or more." >&2
fi

# 4. AFL++ core pattern (host sysctl, warn only -- not needed unless fuzzing).
if [ -r /proc/sys/kernel/core_pattern ]; then
    cp=$(cat /proc/sys/kernel/core_pattern)
    case "$cp" in
        core|"") ;;
        *) echo "WARN: kernel.core_pattern='$cp'. afl-fuzz will refuse to start." >&2
           echo "      On the HOST run: sudo sysctl -w kernel.core_pattern=core" >&2 ;;
    esac
fi

[ "$fail" -eq 0 ] || exit 1
exec "$@"
