#!/usr/bin/env bash
# Baseline sweep: what each technique finds on its own, before any agent.
set -u
cd "$(dirname "$0")/../host_twin" || exit 1
make -s all || exit 1
chmod +x target_tsan target_asan target_plain fuzz_stdin 2>/dev/null
for b in target_tsan target_asan fuzz_stdin; do
  [ -x "./$b" ] || { echo "FATAL: ./$b is not executable (noexec mount?)"; exit 1; }
done

echo "== 1. TSan (race detection) =="
./target_tsan race 40 1 2>&1 | grep -E "SUMMARY|Location is" || echo "  NO RACE REPORTED - harness problem, fix before adding an agent"

echo; echo "== 2. ASan + widened window (BUG-001 PoC) =="
./target_asan race 20 1 2>&1 | grep -E "ERROR:|in handle_frame" | head -3 || echo "  no crash"

echo; echo "== 3. Sequential PoC (BUG-002) =="
printf '\x00\xc0\x00\x3d' > /tmp/poc.bin; head -c 61 /dev/zero >> /tmp/poc.bin
./fuzz_stdin < /tmp/poc.bin 2>&1 | grep -E "ERROR:|in parse_config" | head -2 || echo "  no crash"

echo; echo "== 4. angr (directed solve for BUG-002) =="
python3 ../agent/solve_parse_config.py ./target_plain 64 2>/dev/null | tail -4
