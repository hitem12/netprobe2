#!/usr/bin/env bash
set -euo pipefail

echo "==> netprobe devcontainer setup"

# ── Conan home ─────────────────────────────────────────────
export CONAN_HOME=/workspace/.conan2
mkdir -p "${CONAN_HOME}"

# persist across container sessions
#if ! grep -q "CONAN_HOME" /etc/environment 2>/dev/null; then
#    echo "CONAN_HOME=/workspace/.conan2" >> /etc/environment
#fi

# ── Conan profile ──────────────────────────────────────────
echo "==> Configuring Conan profile..."
conan profile detect --force

# append [conf] only if not already present
if ! grep -q "tools.system.package_manager:mode" \
        "${CONAN_HOME}/profiles/default"; then
    cat >> "${CONAN_HOME}/profiles/default" << 'EOF'

[conf]
tools.system.package_manager:mode=check
tools.system.package_manager:sudo=True
EOF
fi

echo "==> Conan profile:"
conan profile show

# ── Conan install ──────────────────────────────────────────
echo "==> Installing Conan dependencies..."
conan install . \
    --build=missing \
    --settings=build_type=Debug

## ── CMake configure ────────────────────────────────────────
#echo "==> Configuring CMake..."
#if grep -q "conan-debug" CMakePresets.json 2>/dev/null || \
#   grep -q "conan-debug" build/Debug/CMakePresets.json 2>/dev/null; then
#    cmake --preset conan-debug
#else
#    cmake -S . -B build/Debug \
#        -DCMAKE_TOOLCHAIN_FILE=build/Debug/conan_toolchain.cmake \
#        -DCMAKE_BUILD_TYPE=Debug \
#        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
#        -G Ninja
#fi
#
## ── compile_commands symlink ───────────────────────────────
#ln -sf build/Debug/compile_commands.json compile_commands.json \
#    2>/dev/null || true

echo ""
echo "==> Done. Build with:"
echo "    cmake --build build/Debug"
echo "    ctest --test-dir build/Debug"