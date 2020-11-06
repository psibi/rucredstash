#!/usr/bin/env bash

set -e

cargo build

CREDSTASH=rucredstash

$CREDSTASH --version

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

$CREDSTASH putall '{"hello":"world","hi":"bye"}'
$CREDSTASH getall > secrets.json

$CREDSTASH delete hello
$CREDSTASH delete hi

$CREDSTASH putall @secrets.json
rm secrets.json

$CREDSTASH getall
$CREDSTASH delete hello
$CREDSTASH delete hi

echo "Test succesffuly executed"
