#!/usr/bin/env bash
# Baseline sweep: what each technique finds on its own, before any agent.
set -u
cd "$(dirname "$0")/../host_twin" || exit 1
make -s all || exit 1
chmod +x target_tsan target_asan target_plain fuzz_stdin 2>/dev/null
for b in target_tsan target_asan fuzz_stdin; do
  [ -x "./$b" ] || { echo "FATAL: ./$b is not executable (noexec mount?)"; exit 1; }
done

# Host-built and container-built binaries share this bind mount but not their
# sanitizer runtimes (libasan.so.6 on 22.04 vs .so.8 on 24.04). Whichever was
# built last wins, make sees it as newer than the sources and skips the
# rebuild, and every track below dies at the loader. Catch that here rather
# than reporting it as "no crash".
for b in target_tsan target_asan fuzz_stdin; do
  err=$(./"$b" </dev/null 2>&1)
  case "$err" in
    *"error while loading shared libraries"*)
      echo "FATAL: ./$b will not load in this environment:"
      printf '       %s\n' "$(printf '%s\n' "$err" | head -1)"
      echo "       It was built by a different toolchain (host vs container)."
      echo "       Fix: make -C host_twin clean, then re-run this script."
      exit 1 ;;
  esac
done

# Print matching lines, or the given fallback if there are none. Do NOT inline
# this as `cmd | grep -E ... | head -n || echo fallback`: the pipeline's status
# is head's, which is always 0, so the fallback is dead code and a silent
# harness failure is indistinguishable from a clean run.
report() {
  local pattern=$1 lines=$2 fallback=$3 out=$4 hit
  # A sanitizer that dies at startup produces no matching lines, so without
  # this it renders as the benign fallback ("no race", "no crash") -- the exact
  # silent-failure mode this script exists to prevent. TSan's shadow-mapping
  # failure is ASLR-layout-dependent and hits ~2 runs in 3, so it looks like
  # flakiness rather than misconfiguration.
  case "$out" in
    *"unexpected memory mapping"*|*"FATAL: ThreadSanitizer"*|*"Shadow memory range interleaves"*)
      echo "  FATAL: sanitizer could not map shadow memory -- result is not a"
      echo "         negative, it is a broken run. Intermittent by nature, so"
      echo "         a later clean pass does not mean this is fixed."
      echo "         On the HOST run: sudo sysctl -w vm.mmap_rnd_bits=28"
      return 1 ;;
  esac
  hit=$(printf '%s\n' "$out" | grep -E "$pattern" | head -"$lines")
  if [ -n "$hit" ]; then printf '%s\n' "$hit"; else echo "  $fallback"; fi
}

echo "== 1. TSan (race detection) =="
report "SUMMARY|Location is" 4 \
  "NO RACE REPORTED - harness problem, fix before adding an agent" \
  "$(./target_tsan race 40 1 2>&1)"

echo; echo "== 2. ASan + widened window (BUG-001 PoC) =="
report "ERROR:|in handle_frame" 3 "no crash" \
  "$(./target_asan race 20 1 2>&1)"

echo; echo "== 3. Sequential PoC (BUG-002) =="
printf '\x00\xc0\x00\x3d' > /tmp/poc.bin; head -c 61 /dev/zero >> /tmp/poc.bin
report "ERROR:|in parse_config" 2 "no crash" \
  "$(./fuzz_stdin < /tmp/poc.bin 2>&1)"

echo; echo "== 4. angr (directed solve for BUG-002) =="
python3 ../agent/solve_parse_config.py ./target_plain 64 2>/dev/null | tail -4

echo; echo "== 5. Credential-store race (BUG-003) =="
ctl=$(./target_asan cred-baseline 500 2>&1); ctl_rc=$?
esc=$(./target_asan cred 20 1 2>&1);         esc_rc=$?
echo "  $ctl"
echo "  $esc"
if [ "$ctl_rc" -eq 0 ] && [ "$esc_rc" -eq 1 ]; then
  echo "  PRIVILEGE ESCALATION: admin granted for a non-admin record, and the"
  echo "  sequential control is clean -- concurrency is the cause."
else
  echo "  no escalation (control rc=$ctl_rc, concurrent rc=$esc_rc)"
fi
