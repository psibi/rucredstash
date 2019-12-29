#!/usr/bin/env bash

set -eux

rm -rf "${BUILD_BINARIESDIRECTORY}"
mkdir "${BUILD_BINARIESDIRECTORY}"

cargo build --release

if [[ -f "target/release/rucredstash.exe" ]]; then
  mv "target/release/rucredstash.exe" "${BUILD_BINARIESDIRECTORY}/"
else
  mv "target/release/rucredstash" "${BUILD_BINARIESDIRECTORY}/"
fi
