#!/bin/bash
# Wrapper for fw_setenv – blocks options, especially script-file mode.
set -efuo pipefail

FW_SETENV=/usr/bin/fw_setenv

usage() {
    echo "Usage: $0 <key> <value>" >&2
    exit 1
}

# sudo matches command line arguments as one concatenated string, so a wildcard
# rule can pass more than the two expected arguments
[[ $# -ne 2 ]] && usage

KEY="$1"
VALUE="$2"

# fw_setenv parses with getopt, which also accepts -sFILE and --scr=FILE,
# so '--' is what keeps key and value as data
exec "$FW_SETENV" -- "$KEY" "$VALUE"
