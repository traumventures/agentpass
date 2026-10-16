#!/bin/sh
# Installs the latest agentpass release binary.
#
#   curl -fsSL https://raw.githubusercontent.com/traumventures/agentpass/main/install.sh | sh
#
# Environment: AGENTPASS_INSTALL_DIR (default ~/.local/bin),
#              AGENTPASS_VERSION (default: latest, e.g. v0.2.0).
set -eu

repo="traumventures/agentpass"
dir="${AGENTPASS_INSTALL_DIR:-$HOME/.local/bin}"
version="${AGENTPASS_VERSION:-latest}"

case "$(uname -s)" in
  Linux) os="unknown-linux-gnu" ;;
  Darwin) os="apple-darwin" ;;
  *) echo "agentpass supports Linux and macOS only" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch="x86_64" ;;
  arm64 | aarch64) arch="aarch64" ;;
  *) echo "unsupported CPU architecture: $(uname -m)" >&2; exit 1 ;;
esac
target="$arch-$os"
asset="agentpass-$target.tar.gz"
if [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $asset ($version)..."
curl -fsSL "$base/$asset" -o "$tmp/$asset"
curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256"

expected="$(cut -d ' ' -f 1 < "$tmp/$asset.sha256")"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp/$asset" | cut -d ' ' -f 1)"
else
  actual="$(shasum -a 256 "$tmp/$asset" | cut -d ' ' -f 1)"
fi
if [ "$expected" != "$actual" ]; then
  echo "checksum mismatch for $asset" >&2
  exit 1
fi

tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$dir"
install -m 0755 "$tmp/agentpass-$target/agentpass" "$dir/agentpass"
echo "Installed $("$dir/agentpass" --version) to $dir/agentpass"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Add $dir to your PATH, e.g.: export PATH=\"$dir:\$PATH\"" ;;
esac
echo "Next: agentpass setup   (then: agentpass init-skill)"
