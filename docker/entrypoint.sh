#!/usr/bin/env bash
# Preflight. The failure modes below are silent and waste hours: a container
# where the sanitizers cannot map shadow memory just reports "no bugs found",
# which is indistinguishable from a working run that found nothing.
set -euo pipefail

fail=0

# 1. ASLR entropy. Kernels 6.5+ default vm.mmap_rnd_bits=32, which collides
#    with the ASan/TSan shadow mapping. This is a HOST sysctl -- it cannot be
#    fixed from inside the container. See docker/host-setup.sh.
#
#    Do NOT test this by reading /proc/sys/vm/mmap_rnd_bits: it is mode 0600
#    root, so as the `esc` user the read fails, the check skips itself, and
#    the preflight passes while TSan is broken. Test TSan for real instead.
#
#    The failure is layout-dependent, so it is INTERMITTENT -- roughly 2 in 3
#    runs on a stock 6.8 kernel. One successful run proves nothing, hence the
#    loop.
cat > /tmp/_t.c <<'EOC'
#include <pthread.h>
static int g;
static void *f(void *a) { (void)a; g++; return 0; }
int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, 0, f, 0); pthread_create(&t2, 0, f, 0);
    pthread_join(t1, 0); pthread_join(t2, 0);
    return 0;
}
EOC
if gcc -fsanitize=thread -o /tmp/_t /tmp/_t.c 2>/dev/null; then
    tsan_fails=0
    for _ in 1 2 3 4 5 6; do
        # Capture, then match. Do NOT pipe into grep: `set -o pipefail` is on,
        # TSan's FATAL exits 1, and pipefail propagates that nonzero status
        # even when grep matched -- so the `if` reads false and every failure
        # is counted as a pass. Same trap as report() in scripts/run_all.sh.
        probe=$(/tmp/_t 2>&1 || true)
        case "$probe" in
            *"unexpected memory mapping"*) tsan_fails=$((tsan_fails + 1)) ;;
        esac
    done
    if [ "$tsan_fails" -gt 0 ]; then
        if [ "${ESC26_SKIP_TSAN_CHECK:-0}" = "1" ]; then
            echo "WARN: TSan failed to map shadow memory in $tsan_fails/6 runs," >&2
            echo "      but ESC26_SKIP_TSAN_CHECK=1 is set, so continuing." >&2
            echo "      The TSan track is UNRELIABLE in this container: treat a" >&2
            echo "      'no race' result as no result at all." >&2
        else
            echo "FATAL: ThreadSanitizer failed to map shadow memory in $tsan_fails/6 runs." >&2
            echo "       ASLR entropy is too high for the TSan shadow layout." >&2
            echo "       The TSan track will report 'no race' at random, which is" >&2
            echo "       why this is fatal rather than a warning." >&2
            echo "       On the HOST run: sudo sysctl -w vm.mmap_rnd_bits=28" >&2
            echo "       (or: sudo bash docker/host-setup.sh)" >&2
            echo "" >&2
            echo "       The ASan, angr and fuzzing tracks are unaffected. To use" >&2
            echo "       just those, re-run with ESC26_SKIP_TSAN_CHECK=1." >&2
            fail=1
        fi
    fi
fi
rm -f /tmp/_t /tmp/_t.c

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
# NOTE: plain `nproc` honours OMP_NUM_THREADS, which docker-compose.yml pins to
# 1 to keep angr from eating every core -- so it reports "1 CPU" on every run
# and the warning below would be permanent noise. Read the real limit instead:
# the affinity mask, capped by the cgroup CPU quota (compose `cpus:`).
cpus=$(OMP_NUM_THREADS= nproc)
if [ -r /sys/fs/cgroup/cpu.max ]; then
    read -r quota period < /sys/fs/cgroup/cpu.max
    if [ "$quota" != "max" ] && [ "$period" -gt 0 ] 2>/dev/null; then
        q=$(( quota / period ))
        [ "$q" -lt 1 ] && q=1
        [ "$q" -lt "$cpus" ] && cpus=$q
    fi
fi
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
