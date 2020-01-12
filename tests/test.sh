#!/usr/bin/env bash

set -e

cargo build

CREDSTASH=../target/debug/rucredstash

$CREDSTASH put hi bye
$CREDSTASH get hi
$CREDSTASH getall
$CREDSTASH keys
$CREDSTASH list
$CREDSTASH delete hi

$CREDSTASH put nasdaq nifty500 market=world
$CREDSTASH put vanguard vanguardsecret market=world indexfunds=us

$CREDSTASH get nasdaq market=world
$CREDSTASH get vanguard market=world indexfunds=us

$CREDSTASH delete nasdaq
$CREDSTASH delete vanguard
echo "Test succesffuly executed"
