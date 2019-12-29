#!/usr/bin/env bash

set -eux

cargo build --release

rm -rf "${BUILD_BINARIESDIRECTORY}"
mkdir "${BUILD_BINARIESDIRECTORY}"

if [[ -f "target/release/credstash.exe" ]]; then
  mv "target/release/credstash.exe" 
else
  mv "target/release/credstash" "${BUILD_BINARIESDIRECTORY}/"
fi
