FROM ubuntu:26.04

ARG DEBIAN_FRONTEND=noninteractive

COPY . /opt/aifuzz
WORKDIR /opt/aifuzz

RUN apt-get update -qq && \
    apt-get install -y -qq curl git build-essential clang clang-tools cmake ninja-build \
      llvm libssl-dev pkg-config python3-yaml python3-pytest python3-pip \
      libpng-dev binutils-dev libunwind-dev afl++ && \
    AIFUZZ_BUILD_HONGGFUZZ=1 bash scripts/setup_wsl.sh && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

CMD ["python3", "tools/harness_check.py", "--crash-timeout", "30", "--smoke-box", "20"]
