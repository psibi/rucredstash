#!/usr/bin/env bash

set -eux



rm -rf "${BUILD_BINARIESDIRECTORY}"
mkdir "${BUILD_BINARIESDIRECTORY}"

ls .

cargo build --release

if [[ -f "target/release/credstash.exe" ]]; then
  mv "target/release/credstash.exe" 
else
  mv "target/release/credstash" "${BUILD_BINARIESDIRECTORY}/"
fi
