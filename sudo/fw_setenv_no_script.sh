#!/bin/bash
# Wrapper for fw_setenv – blocks options, especially script-file mode.
set -efuo pipefail

FW_SETENV=/usr/bin/fw_setenv

usage() {
    echo "Usage: $0 <key> <value>" >&2
    echo "       Script-file mode is not permitted." >&2
    exit 1
}

[[ $# -ne 2 ]] && usage

KEY="$1"
VALUE="$2"

# '--' ends option parsing, so key and value are always treated as data.
# this blocks script mode and every other option, e.g. an attacker-chosen
# config file, which a flag blocklist would miss (getopt accepts attached
# values like -sFILE and abbreviations like --scr=FILE)
exec "$FW_SETENV" -- "$KEY" "$VALUE"
