#!/usr/bin/env bash
# Drive the tool layer from the host, executing inside the analysis container.
#
#   scripts/tool.sh list_files
#   scripts/tool.sh run_interleaving '{"iters": 20, "widen": 1}'
#
# ESC26_SKIP_TSAN_CHECK is passed through: the TSan track needs
# vm.mmap_rnd_bits=28 on the host, and without it the preflight refuses to run.
set -u
cd "$(dirname "$0")/.." || exit 1
exec docker compose -f docker/docker-compose.yml run --rm -T \
  -e ESC26_SKIP_TSAN_CHECK="${ESC26_SKIP_TSAN_CHECK:-0}" \
  analysis python3 agent/toolcli.py "$@"
