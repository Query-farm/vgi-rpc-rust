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
  *-pc-windows-msvc)
    static_library=vgi_iroh_cabi.lib
    ;;
  *)
    static_library=libvgi_iroh_cabi.a
    ;;
esac

library_path="$cargo_target_dir/$target_triple/release/$static_library"
header_path="vgi-iroh-cabi/include/vgi_iroh.h"
if [ ! -f "$library_path" ]; then
  echo "missing C ABI static library: $library_path" >&2
  exit 1
fi
if [ ! -f "$header_path" ]; then
  echo "missing C ABI header: $header_path" >&2
  exit 1
fi

package_name="vgi-iroh-cabi-v${version}-${target_triple}"
staging_root=$(mktemp -d)
trap 'rm -rf "$staging_root"' EXIT
package_root="$staging_root/$package_name"
mkdir -p "$package_root/include" "$package_root/lib"
cp "$header_path" "$package_root/include/vgi_iroh.h"
cp "$library_path" "$package_root/lib/$static_library"
cp LICENSE NOTICE "$package_root/"
{
  echo "package=vgi-iroh-cabi"
  echo "version=$version"
  echo "abi_version=1"
  echo "target=$target_triple"
  echo "commit=$commit"
  echo "linkage=static"
} > "$package_root/manifest.txt"

mkdir -p "$output_dir"
archive="$output_dir/$package_name.tar.gz"
tar -C "$staging_root" -czf "$archive" "$package_name"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_dir" && sha256sum "$(basename "$archive")") > "$archive.sha256"
else
  (cd "$output_dir" && shasum -a 256 "$(basename "$archive")") > "$archive.sha256"
fi
