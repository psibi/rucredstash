#!/usr/bin/env bash

set -eux

cargo install --path . --force

rm -rf "${BUILD_BINARIESDIRECTORY}"
mkdir "${BUILD_BINARIESDIRECTORY}"

if [[ -f "target/release/credstash.exe" ]]; then
  mv "target/release/credstash.exe" "${BUILD_BINARIESDIRECTORY}/"
else
  mv "target/release/credstash" "${BUILD_BINARIESDIRECTORY}/"
fi
