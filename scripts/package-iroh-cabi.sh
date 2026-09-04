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
    link_library=vgi_iroh_cabi.lib
    runtime_library=vgi_iroh_cabi.dll
    runtime_subdirectory=bin
    ;;
  *-apple-darwin)
    link_library=libvgi_iroh_cabi.a
    runtime_library=libvgi_iroh_cabi.dylib
    runtime_subdirectory=lib
    ;;
  *)
    link_library=libvgi_iroh_cabi.a
    runtime_library=libvgi_iroh_cabi.so
    runtime_subdirectory=lib
    ;;
esac

library_path="$cargo_target_dir/$target_triple/release/$link_library"
runtime_library_path="$cargo_target_dir/$target_triple/release/$runtime_library"
header_path="vgi-iroh-cabi/include/vgi_iroh.h"
if [ ! -f "$library_path" ]; then
  echo "missing C ABI link library: $library_path" >&2
  exit 1
fi
if [ ! -f "$runtime_library_path" ]; then
  echo "missing C ABI runtime library: $runtime_library_path" >&2
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
mkdir -p "$package_root/include" "$package_root/lib" "$package_root/$runtime_subdirectory"
cp "$header_path" "$package_root/include/vgi_iroh.h"
cp "$library_path" "$package_root/lib/$link_library"
cp "$runtime_library_path" "$package_root/$runtime_subdirectory/$runtime_library"
if [[ "$target_triple" == *-pc-windows-msvc ]]; then
  import_count=0
  while IFS= read -r manifest_path; do
    for import_library in "$(dirname "$manifest_path")"/lib/windows.*.lib; do
      if [ -f "$import_library" ]; then
        cp "$import_library" "$package_root/lib/"
        import_count=$((import_count + 1))
      fi
    done
  done < <(cargo metadata --locked --format-version 1 \
    | jq -r '.packages[] | select(.name=="windows_x86_64_msvc") | .manifest_path')
  if [ "$import_count" -eq 0 ]; then
    echo "no versioned windows_x86_64_msvc import libraries found via cargo metadata" >&2
    exit 1
  fi
fi
mkdir -p "$package_root/lib/cmake/vgi_iroh_cabi"
cp vgi-iroh-cabi/cmake/vgi_iroh_cabi-config.cmake \
  "$package_root/lib/cmake/vgi_iroh_cabi/"
cp LICENSE NOTICE "$package_root/"
cargo tree -p vgi-iroh-cabi --edges normal,build --prefix none \
  --format $'{p}\t{l}\t{r}' | sort -u > "$package_root/THIRD_PARTY_LICENSES.tsv"
{
  echo "package=vgi-iroh-cabi"
  echo "version=$version"
  echo "abi_version=1"
  echo "target=$target_triple"
  echo "commit=$commit"
  echo "linkage=static,shared"
  echo "runtime_library=$runtime_subdirectory/$runtime_library"
} > "$package_root/manifest.txt"

mkdir -p "$output_dir"
archive="$output_dir/$package_name.tar.gz"
tar -C "$staging_root" -czf "$archive" "$package_name"
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_dir" && sha256sum "$(basename "$archive")") > "$archive.sha256"
else
  (cd "$output_dir" && shasum -a 256 "$(basename "$archive")") > "$archive.sha256"
fi
