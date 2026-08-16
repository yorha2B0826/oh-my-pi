#!/bin/sh
set -e

# OMP (USTC iWAN fork) Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/yorha2B0826/oh-my-pi/main/scripts/install.sh | sh
#
# 从 fork 的 GitHub Releases 下载预编译二进制(含 iWAN/USTC 定制),
# 安装到 ~/.local/bin/omp。
#
# Options:
#   --ref <ref>    Install specific release tag (default: latest)
#   -r <ref>       Shorthand for --ref
#   --version      Print installer version

REPO="yorha2B0826/oh-my-pi"
INSTALL_DIR="${PI_INSTALL_DIR:-$HOME/.local/bin}"
# GitHub 下载镜像前缀(可选):国内网络不稳定时可设
#   export GH_MIRROR="https://gh-proxy.com/"   (注意结尾斜杠)
# 空则直连 github.com
GH_MIRROR="${GH_MIRROR:-}"

# Parse arguments
REF=""
while [ $# -gt 0 ]; do
    case "$1" in
        --ref)
            shift
            if [ -z "$1" ]; then
                echo "Missing value for --ref"
                exit 1
            fi
            REF="$1"
            shift
            ;;
        --ref=*)
            REF="${1#*=}"
            shift
            ;;
        -r)
            shift
            if [ -z "$1" ]; then
                echo "Missing value for -r"
                exit 1
            fi
            REF="$1"
            shift
            ;;
        --version)
            echo "omp (USTC iWAN fork) installer 1.0"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Normalized host architecture (x64|arm64). On macOS this uses
# `sysctl hw.optional.arm64` so it stays correct inside a Rosetta session,
# where `uname -m` reports the translated x86_64.
host_arch() {
    if [ "$(uname -s)" = "Darwin" ]; then
        if [ "$(sysctl -in hw.optional.arm64 2>/dev/null || /usr/sbin/sysctl -in hw.optional.arm64 2>/dev/null)" = "1" ]; then
            echo "arm64"
        else
            echo "x64"
        fi
        return
    fi
    case "$(uname -m)" in
        x86_64|amd64)  echo "x64" ;;
        arm64|aarch64) echo "arm64" ;;
        *)             uname -m ;;
    esac
}

# Detect platform
OS="$(uname -s)"
ARCH="$(host_arch)"

case "$OS" in
    Linux)  PLATFORM="linux" ;;
    Darwin) PLATFORM="darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
    x64|arm64) ;;
    *)         echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# fork 不发布 darwin-x64(Intel Mac)资产——GitHub 已退役 macos-13 runner
if [ "$PLATFORM" = "darwin" ] && [ "$ARCH" = "x64" ]; then
    echo "✗ 本 fork 不提供 Intel Mac (darwin-x64) 二进制(GitHub 已退役 macos-13 runner)。"
    echo "  请使用 Apple Silicon Mac,或改用上游 https://omp.sh/install"
    exit 1
fi

# fork 不发布 musl 二进制,Linux 均使用 glibc 版本
BINARY="omp-${PLATFORM}-${ARCH}"

# Get release tag
if [ -n "$REF" ]; then
    echo "Fetching release $REF..."
    if RELEASE_JSON=$(curl -fsSL --connect-timeout 10 --max-time 60 "https://api.github.com/repos/${REPO}/releases/tags/${REF}"); then
        LATEST=$(echo "$RELEASE_JSON" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    else
        echo "Release tag not found: $REF"
        exit 1
    fi
else
    echo "Fetching latest release..."
    RELEASE_JSON=$(curl -fsSL --connect-timeout 10 --max-time 60 "https://api.github.com/repos/${REPO}/releases/latest")
    LATEST=$(echo "$RELEASE_JSON" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
fi

if [ -z "$LATEST" ]; then
    echo "Failed to fetch release tag"
    exit 1
fi
echo "Using version: $LATEST"

mkdir -p "$INSTALL_DIR"
# Download binary (with retry; direct github.com can be flaky from CN networks)
BINARY_URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}"
EFFECTIVE_URL="${GH_MIRROR}${BINARY_URL}"
echo "Downloading ${BINARY}..."
if [ -n "$GH_MIRROR" ]; then
    echo "  via mirror: ${GH_MIRROR}"
fi
DOWNLOADED=0
for attempt in 1 2 3 4 5; do
    # -C - 断点续传:网络中断后从断点继续,避免每次重下整个二进制
    if curl -fsSL --connect-timeout 10 --speed-limit 1024 --speed-time 30 -C - \
        "$EFFECTIVE_URL" -o "${INSTALL_DIR}/omp"; then
        DOWNLOADED=1
        break
    fi
    echo "  download interrupted (attempt $attempt/5), resuming in 3s..."
    sleep 3
done
if [ "$DOWNLOADED" -ne 1 ]; then
    echo ""
    echo "✗ 下载失败。网络不稳定时可改用镜像重试:"
    echo "    export GH_MIRROR=\"https://gh-proxy.com/\""
    echo "    curl -fsSL https://raw.githubusercontent.com/yorha2B0826/oh-my-pi/main/scripts/install.sh | sh"
    exit 1
fi
chmod +x "${INSTALL_DIR}/omp"

# Verify the freshly installed binary can actually start before reporting success.
if ! SMOKE_OUTPUT="$("${INSTALL_DIR}/omp" --version 2>&1)"; then
    echo ""
    echo "✗ omp was downloaded to ${INSTALL_DIR}/omp but cannot start:"
    echo "$SMOKE_OUTPUT" | sed 's/^/    /'
    echo ""
    echo "  Linux musl (Alpine) 用户:fork 二进制链接 glibc,请安装 glibc 兼容层"
    echo "  或用上游官方版 https://omp.sh/install"
    exit 1
fi

echo ""
echo "✓ Installed omp (USTC iWAN fork) ${LATEST} to ${INSTALL_DIR}/omp"
echo "  Run 'omp' to get started!"
echo ""
echo "  若 ${INSTALL_DIR} 不在 PATH 中,可执行:"
echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
echo ""
echo "  使用 USTC iWAN:"
echo "    omp iwan login"
echo "    omp iwan connect"
