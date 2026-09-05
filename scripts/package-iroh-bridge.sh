#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 5 ]; then
  echo "usage: $0 <target-triple> <version> <commit> <cargo-target-dir> <output-dir>" >&2
  exit 2
fi

target_triple=$1
version=${2#v}
commit=$3
cargo_target_dir=$4
output_dir=$5

case "$target_triple" in
  *-pc-windows-msvc) executable=vgi-iroh-bridge.exe ;;
  *) executable=vgi-iroh-bridge ;;
esac

binary_path="$cargo_target_dir/$target_triple/release/$executable"
if [ ! -f "$binary_path" ]; then
  echo "missing bridge executable: $binary_path" >&2
  exit 1
fi

package_name="vgi-iroh-bridge-v${version}-${target_triple}"
staging_root=$(mktemp -d)
trap 'rm -rf "$staging_root"' EXIT
package_root="$staging_root/$package_name"
mkdir -p "$package_root/bin"
cp "$binary_path" "$package_root/bin/$executable"
cp vgi-iroh-bridge/README.md LICENSE NOTICE "$package_root/"
cargo tree -p vgi-iroh-bridge --edges normal,build --prefix none \
  --format $'{p}\t{l}\t{r}' | sort -u > "$package_root/THIRD_PARTY_LICENSES.tsv"
{
  echo "package=vgi-iroh-bridge"
  echo "version=$version"
  echo "target=$target_triple"
  echo "commit=$commit"
  echo "executable=bin/$executable"
} > "$package_root/manifest.txt"

mkdir -p "$output_dir"
archive="$output_dir/$package_name.tar.gz"
tar -C "$staging_root" -czf "$archive" "$package_name"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_dir" && sha256sum "$(basename "$archive")") > "$archive.sha256"
else
  (cd "$output_dir" && shasum -a 256 "$(basename "$archive")") > "$archive.sha256"
fi
