# README step 13 -- deterministic interleaving driver for BUG-001.
#
# On the host twin the race window is forced open with g_widen_window and
# usleep(). Neither exists here, and TSan has no Xtensa port. Breakpoints are
# the interleaving control instead: stop the consumer between its CHECK and
# its USE, fire the RFID ISR by hand with an oversized frame, then let the
# consumer run on into a memcpy whose length it believes it already validated.
#
# No source instrumentation is involved, which is the point -- the technique
# transfers to the real challenge firmware, where you cannot add sleeps.
#
#   idf.py qemu --gdb            # terminal 1, waits for :3333
#   xtensa-esp32-elf-gdb -batch -x interleave.gdb build/esc26_testbed.elf

set pagination off
set confirm off

target remote :3333

# --- Phase 1: reach the window at all ------------------------------------
# g_len is 0 at boot, so handle_frame bails at the CHECK and the memcpy line
# is unreachable. Prime the shared state with a LEGAL frame first, exactly as
# a real MFRC522 read would, so the consumer passes its own bounds check.
break app_main.c:42
continue

printf "\n=== phase 1: priming with a legal 8-byte frame ===\n"
call rfid_isr_handler((void *) 8)
printf "g_len = %d (legal, <= LOCAL_MAX)\n", g_len

# Execute the CHECK read so the validated copy n picks up the legal value.
next
printf "validated n = %d\n", n

# --- Phase 2: land the ISR inside the window -----------------------------
delete breakpoints
break app_main.c:44
continue

printf "\n=== phase 2: stopped between CHECK and USE ===\n"
printf "validated n = %d   g_len = %d\n", n, g_len
printf "destination local[] is %d bytes\n", (int) sizeof(local)
printf "stack before overflow:\n"
x/32xb local

printf "\n=== firing rfid_isr_handler(64) inside the window ===\n"
call rfid_isr_handler((void *) 64)
printf "g_len = %d   <-- grew; validated n is still %d\n", g_len, n

# --- Phase 3: the USE, with the stale validation -------------------------
next
printf "\n=== after memcpy(local, g_frame, g_len) ===\n"
printf "stack after overflow (0x41 past offset %d proves the overrun):\n", (int) sizeof(local)
x/32xb local

printf "\n=== BUG-001 reproduced on Xtensa, no source instrumentation ===\n"
detach
quit
