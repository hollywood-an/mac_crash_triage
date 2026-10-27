#!/bin/sh
# Runs every crasher once (the versioned v1 build twice, so one cluster has a
# count above 1). Each crash makes macOS's ReportCrash write a new .ips file to
# ~/Library/Logs/DiagnosticReports a few seconds later. Nothing in that folder is
# modified or deleted by this script.
set -u
cd "$(dirname "$0")/build"

ulimit -c 0 # no core files

run() {
    "$@" >/dev/null 2>&1
    echo "$1 exited with status $?"
    sleep 2 # keep reports for the same process in different seconds
}

run ./ct-crasher-segv
run ./ct-crasher-bus
run ./ct-crasher-trap
run ./ct-crasher-overflow
run ./ct-crasher-throw
run ./ct-crasher-swift
run ./versioned-v1/ct-crasher-versioned
run ./versioned-v1/ct-crasher-versioned
run ./versioned-v2/ct-crasher-versioned
run ./stripped-v1/ct-crasher-stripped
run ./stripped-v2/ct-crasher-stripped
