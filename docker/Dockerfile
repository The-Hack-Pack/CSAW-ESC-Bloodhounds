# Analysis container: host twin, sanitizers, fuzzers, angr, agent.
#
# Everything here is a native x86-64 build. The Xtensa/ESP32 side lives in
# Dockerfile.esp32 -- deliberately a separate image, because the ESP-IDF
# toolchain is ~2 GB and you rebuild the analysis image far more often.
#
# libclang-rt-dev is required for -fsanitize=fuzzer,address: the `clang`
# package alone omits libclang_rt.fuzzer/asan and the link fails.
# The -17- variant is separate and NOT redundant: Ubuntu builds afl++
# against LLVM 17, so afl-clang-fast looks for its runtimes under
# /usr/lib/llvm-17 while plain clang is 18. Both are needed.
# Package names below were verified on Ubuntu 24.04 / GCC 13.3 / Clang 18.1.3 /
# AFL++ 4.09c. Apt versions are deliberately NOT pinned -- archive.ubuntu.com
# drops superseded point releases and the build would break within months. For
# true reproducibility pin the base image by digest instead:
#   FROM ubuntu:24.04@sha256:<digest>

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# --- toolchain -------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        libclang-rt-dev \
        libclang-rt-17-dev \
        afl++ \
        gdb \
        make \
        git \
        ca-certificates \
        python3 \
        python3-pip \
        python3-dev \
        file \
        xxd \
    && rm -rf /var/lib/apt/lists/*

# --- python analysis stack -------------------------------------------------
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt \
    && python3 -c "import angr; print('angr', angr.__version__)"

# --- non-root user ---------------------------------------------------------
# Sanitizers and AFL++ both behave better outside root, and it keeps files
# written to the bind mount owned by you rather than root.
ARG UID=1001
ARG GID=1001
# ubuntu:24.04 ships a default `ubuntu` user at UID/GID 1000, which collides
# with the common host UID. Evict whoever holds the ids before claiming them,
# otherwise groupadd exits 4 and the build dies on the most ordinary laptop.
RUN if getent passwd ${UID} >/dev/null; then \
        userdel -r "$(getent passwd ${UID} | cut -d: -f1)" 2>/dev/null || true; \
    fi \
 && if getent group ${GID} >/dev/null; then \
        groupdel "$(getent group ${GID} | cut -d: -f1)"; \
    fi \
 && groupadd -g ${GID} esc \
 && useradd -m -u ${UID} -g ${GID} -s /bin/bash esc

# AFL++ in a container cannot read host CPU governor or set core_pattern.
# These are the standard opt-outs; see docker/host-setup.sh for the host side.
ENV AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_NO_AFFINITY=1

# Symbolize sanitizer reports and keep them on stderr where the tool layer
# reads them. abort_on_error keeps the exit code meaningful for validate_poc.
ENV ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_leaks=0 \
    TSAN_OPTIONS=halt_on_error=0:second_deadlock_stack=1

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

WORKDIR /work
USER esc

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
