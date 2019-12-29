#!/usr/bin/env bash

set -eux

cargo install --path . --force

rm -rf "${BUILD_BINARIESDIRECTORY}"
mkdir "${BUILD_BINARIESDIRECTORY}"

if [[ -f "target/${TARGET}/release/credstash.exe" ]]; then
  mv "target/${TARGET}/release/credstash.exe" "${BUILD_BINARIESDIRECTORY}/"
else
  mv "target/${TARGET}/release/credstash" "${BUILD_BINARIESDIRECTORY}/"
fi
