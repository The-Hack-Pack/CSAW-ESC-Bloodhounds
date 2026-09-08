# Convenience wrapper. Everything here shells out to docker compose so that
# `make verify` behaves identically on your laptop and on a teammate's.
#
# Native (no container) equivalents live in host_twin/Makefile.

COMPOSE := docker compose -f docker/docker-compose.yml
RUN     := $(COMPOSE) run --rm analysis

export UID := $(shell id -u)
export GID := $(shell id -g)

.PHONY: help
help:
	@grep -hE '^[a-z0-9-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk -F':.*?## ' '{printf "  %-16s %s\n", $$1, $$2}'

# --------------------------------------------------------------------- setup
.PHONY: host-setup build
host-setup: ## Apply host sysctls sanitizers and AFL++ need (needs sudo)
	sudo bash docker/host-setup.sh

build: ## Build the analysis image
	$(COMPOSE) build analysis

build-esp32: ## Build the ESP-IDF image (~2 GB, unverified)
	$(COMPOSE) build esp32

# ---------------------------------------------------------------- validation
.PHONY: verify shell
verify: ## Run the four-track baseline sweep in the container
	$(RUN) bash scripts/run_all.sh

shell: ## Interactive shell in the analysis container
	$(RUN) bash

# ------------------------------------------------------------------ analysis
.PHONY: fuzz-libfuzzer fuzz-afl symbolic agent
fuzz-libfuzzer: ## 60s libFuzzer run against the host twin
	$(RUN) bash -c 'make -C host_twin fuzz_libfuzzer && \
	  mkdir -p /tmp/corpus && \
	  ./host_twin/fuzz_libfuzzer -max_total_time=60 -print_final_stats=1 /tmp/corpus'

fuzz-afl: ## AFL++ run against the host twin (ctrl-C to stop)
	$(RUN) bash -c 'make -C host_twin fuzz_afl && \
	  mkdir -p /tmp/in /tmp/out && printf "\x00\xc0\x00\x04" > /tmp/in/seed && \
	  afl-fuzz -i /tmp/in -o /tmp/out -- ./host_twin/fuzz_afl'

symbolic: ## angr directed solve for BUG-002
	$(RUN) python3 agent/solve_parse_config.py host_twin/target_plain 64

agent: ## Run the LLM agent loop (needs ANTHROPIC_API_KEY)
	$(COMPOSE) run --rm agent

# --------------------------------------------------------------------- esp32
.PHONY: esp32-build esp32-qemu
esp32-build: ## Build the ESP32 firmware
	$(COMPOSE) run --rm esp32 bash -lc 'idf.py set-target esp32 && idf.py build'

esp32-qemu: ## Boot the firmware under qemu-system-xtensa with a gdbstub on :1234
	$(COMPOSE) run --rm --service-ports esp32 bash -lc 'idf.py qemu --gdb'

# --------------------------------------------------------------------- chores
.PHONY: clean nuke
clean: ## Remove build artifacts
	$(RUN) make -C host_twin clean

nuke: ## Remove images and volumes too
	$(COMPOSE) down -v --rmi local
