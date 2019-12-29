#!/usr/bin/env bash

set -eux

rm -rf "${BUILD_BINARIESDIRECTORY}"
mkdir "${BUILD_BINARIESDIRECTORY}"

cargo install --path "${BUILD_BINARIESDIRECTORY}/" --force

ls "${BUILD_BINARIESDIRECTORY}/"
