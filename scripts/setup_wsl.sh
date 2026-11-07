#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

if ! command -v sudo >/dev/null 2>&1; then
  SUDO=""
else
  SUDO="sudo"
fi

${SUDO} apt-get update -qq
${SUDO} apt-get install -y -qq build-essential clang clang-tools cmake ninja-build \
  llvm libssl-dev pkg-config python3-yaml python3-pytest git

CLANG_MAJOR="$(clang --version 2>/dev/null | head -1 | sed -E 's/.*version ([0-9]+)\..*/\1/' || true)"
if [ -n "${CLANG_MAJOR}" ]; then
  ${SUDO} apt-get install -y -qq "libclang-rt-${CLANG_MAJOR}-dev"
fi

if ! command -v afl-clang-fast >/dev/null 2>&1; then
  if apt-cache show afl++ >/dev/null 2>&1; then
    ${SUDO} apt-get install -y -qq afl++
  else
    BUILD_DIR="$(mktemp -d)"
    ${SUDO} apt-get install -y -qq python3-dev automake libtool libgcrypt20-dev libgmp-dev zlib1g-dev
    git clone --depth=1 --branch v4.33c https://github.com/AFLplusplus/AFLplusplus.git "${BUILD_DIR}/aflpp"
    make -C "${BUILD_DIR}/aflpp" -j"$(nproc)" all
    ${SUDO} make -C "${BUILD_DIR}/aflpp" install
    rm -rf "${BUILD_DIR}"
  fi
fi

if ! command -v hfuzz-clang >/dev/null 2>&1; then
  if apt-cache show honggfuzz >/dev/null 2>&1; then
    ${SUDO} apt-get install -y -qq honggfuzz
  elif [ "${AIFUZZ_BUILD_HONGGFUZZ:-0}" = "1" ]; then
    BUILD_DIR="$(mktemp -d)"
    ${SUDO} apt-get install -y -qq binutils-dev libunwind-dev
    git clone --depth=1 https://github.com/google/honggfuzz.git "${BUILD_DIR}/honggfuzz"
    make -C "${BUILD_DIR}/honggfuzz" -j"$(nproc)"
    ${SUDO} make -C "${BUILD_DIR}/honggfuzz" install
    rm -rf "${BUILD_DIR}"
  fi
fi

LIBPNG16_PREFIX="$HOME/.aifuzz/libs/libpng16"
if [ ! -f "${LIBPNG16_PREFIX}/lib/libpng16.a" ]; then
  BUILD_DIR="$(mktemp -d)"
  curl -sL https://github.com/pnggroup/libpng/archive/refs/heads/libpng16.tar.gz | tar xz -C "${BUILD_DIR}"
  cd "${BUILD_DIR}"/libpng-libpng16
  ./configure CC=clang \
    CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fsanitize=address" \
    --prefix="${LIBPNG16_PREFIX}" --disable-shared --enable-static --disable-tools
  make -j"$(nproc)" > /dev/null
  make install > /dev/null
  cd -
  rm -rf "${BUILD_DIR}"
fi

mkdir -p "$HOME/.aifuzz"
cat > "$HOME/.aifuzz/env.sh" <<EOF
export AIFUZZ_LIBPNG16_INC=${LIBPNG16_PREFIX}/include
export AIFUZZ_LIBPNG16_LIB=${LIBPNG16_PREFIX}/lib/libpng16.a
EOF

echo
echo "toolchain:"
clang --version | head -1
cmake --version | head -1
afl-clang-fast --version 2>/dev/null | head -1 || echo "afl-clang-fast: missing"
hfuzz-clang --version 2>/dev/null | head -1 || echo "hfuzz-clang: missing (set AIFUZZ_BUILD_HONGGFUZZ=1 to build from source)"
echo "aifuzz environment ready"
