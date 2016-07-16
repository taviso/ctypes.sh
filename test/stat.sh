#!/bin/bash

source ctypes.sh

# exit on error
set -e

# Define the format of struct stat for bash
struct -m statbuf stat passwd

# stat is not exported on Linux, use xstat instead.
if test "$(uname)" == "Linux"; then
    dlcall -r int __xstat 0 "/etc/passwd" $statbuf
else
    dlcall -r int stat "/etc/passwd" $statbuf
fi

# Convert result into bash structure
unpack $statbuf passwd

printf "/etc/passwd\n"
printf "\tuid:  %u\n" ${passwd[st_uid]##*:}
printf "\tgid:  %u\n" ${passwd[st_gid]##*:}
printf "\tmode: %o\n" ${passwd[st_mode]##*:}
printf "\tsize: %u\n" ${passwd[st_size]##*:}

dlcall free $statbuf

# Check result is correct
if test ${passwd[st_size]##*:} -eq $(wc -c < /etc/passwd); then
    echo PASS
    exit 0
fi

echo FAIL
exit 1
