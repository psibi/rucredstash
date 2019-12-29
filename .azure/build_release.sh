#!/usr/bin/env bash

set -eux

rm -rf "${BUILD_BINARIESDIRECTORY}"
mkdir "${BUILD_BINARIESDIRECTORY}"

ls .

cargo build --release

ls -R

if [[ -f "target/release/rucredstash.exe" ]]; then
  mv "target/release/rucredstash.exe" 
else
  mv "target/release/rucredstash" "${BUILD_BINARIESDIRECTORY}/"
fi
