#!/usr/bin/env bash
# README step 13, non-interactive: boot the firmware under qemu with a gdbstub
# and drive firmware/interleave.gdb against it to reproduce BUG-001 on Xtensa
# with no source instrumentation. Run inside the esp32 container:
#
#   docker compose -f docker/docker-compose.yml run --rm -T esp32 \
#       bash /work/scripts/esp32_interleave.sh
set -u
cd /work/firmware || exit 1

[ -f build/esc26_testbed.elf ] || { echo "FATAL: build first (idf.py build)"; exit 1; }

GDB=$(command -v xtensa-esp32-elf-gdb || find /opt/esp -name 'xtensa-esp32-elf-gdb' 2>/dev/null | head -1)
[ -n "$GDB" ] || { echo "FATAL: xtensa-esp32-elf-gdb not found"; exit 1; }

# qemu halts at reset waiting for gdb on :3333 (ESP-IDF v5.3 uses tcp::3333).
idf.py qemu --gdb </dev/null >/tmp/qemu.log 2>&1 &
QPID=$!

# Wait for the gdbstub port to open.
up=0
for _ in $(seq 1 40); do
    if (exec 3<>/dev/tcp/127.0.0.1/3333) 2>/dev/null; then exec 3<&- 3>&-; up=1; break; fi
    sleep 1
done
if [ "$up" -ne 1 ]; then
    echo "FATAL: gdbstub never came up on :3333"; echo "--- qemu.log ---"; tail -20 /tmp/qemu.log
    kill "$QPID" 2>/dev/null; exit 1
fi

echo "=== driving interleave.gdb via $GDB ==="
"$GDB" -batch -x interleave.gdb build/esc26_testbed.elf 2>&1
rc=$?

kill "$QPID" 2>/dev/null; wait 2>/dev/null
exit $rc
