CC      ?= gcc
CFLAGS  ?= -g -O0 -pthread
SRC      = target.c
BINS     = target_tsan target_asan target_plain fuzz_stdin

all: $(BINS)

target_tsan:  $(SRC) main.c ; $(CC) $(CFLAGS) -fsanitize=thread   $^ -o $@
target_asan:  $(SRC) main.c ; $(CC) $(CFLAGS) -fsanitize=address  $^ -o $@
target_plain: $(SRC) fuzz_entry.c ; $(CC) $(CFLAGS) -static       $^ -o $@
fuzz_stdin:   $(SRC) fuzz_entry.c ; $(CC) $(CFLAGS) -fsanitize=address $^ -o $@

# clang/AFL++ variants (used once you have them installed - see README step 9)
fuzz_libfuzzer: $(SRC) fuzz_entry.c
	clang $(CFLAGS) -DFUZZING_ENGINE -fsanitize=fuzzer,address $^ -o $@
fuzz_afl: $(SRC) fuzz_entry.c
	afl-clang-fast $(CFLAGS) -fsanitize=address $^ -o $@

clean: ; rm -f $(BINS) fuzz_libfuzzer fuzz_afl
.PHONY: all clean
