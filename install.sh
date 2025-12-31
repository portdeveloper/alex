#!/bin/sh
set -e

REPO="portdeveloper/alex"
BINARY="alex"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  darwin) OS="darwin" ;;
  linux) OS="linux" ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  amd64) ARCH="amd64" ;;
  arm64) ARCH="arm64" ;;
  aarch64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Get latest version
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$VERSION" ]; then
  echo "Failed to get latest version"
  exit 1
fi

echo "Installing alex $VERSION ($OS/$ARCH)..."

# Download URL
URL="https://github.com/$REPO/releases/download/$VERSION/${BINARY}_${OS}_${ARCH}.tar.gz"

# Create temp directory
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# Download and extract
curl -fsSL "$URL" | tar -xz -C "$TMP_DIR"

# Install
INSTALL_DIR="/usr/local/bin"
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/"
else
  echo ""
  echo "Installing to $INSTALL_DIR requires admin privileges."
  echo "Enter your password to continue (or Ctrl+C to cancel):"
  sudo mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/"
fi

echo ""
echo "alex installed successfully!"
echo ""
echo "Get started:"
echo "  alex set MY_SECRET \"secret-value\""
echo "  alex list"
echo "  alex run your-command"
