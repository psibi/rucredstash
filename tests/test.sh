#!/usr/bin/env bash

set -e

CREDSTASH=../target/debug/rucredstash

$CREDSTASH put hi bye
$CREDSTASH get hi
$CREDSTASH getall
$CREDSTASH keys
$CREDSTASH list
$CREDSTASH delete hi

echo "Test succesffuly executed"
