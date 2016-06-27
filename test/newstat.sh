#!/bin/bash

source ../ctypes.sh

# Allocate some space for the stat buffer
dlcall -n statbuf -r pointer malloc 1024

# Define the format of struct stat for bash
struct stat passwd

# stat is not exported, use xstat instead.
dlcall -r int __xstat 0 "/etc/passwd" $statbuf

unpack $statbuf passwd

printf "/etc/passwd\n"
printf "\tuid:  %u\n" ${passwd[st_uid]##*:}
printf "\tgid:  %u\n" ${passwd[st_gid]##*:}
printf "\tmode: %o\n" ${passwd[st_mode]##*:}
printf "\tsize: %u\n" ${passwd[st_size]##*:}

dlcall free $statbuf

if test ${passwd[st_size]##*:} -eq $(wc -c < /etc/passwd); then
    echo PASS
    exit 0
fi

echo FAIL
exit 1
