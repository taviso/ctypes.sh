#!/bin/bash

source ../ctypes.sh

# Allocate some space for the stat buffer
dlcall -n statbuf -r pointer $RTLD_DEFAULT malloc 1024

# Define the format of struct stat for bash
declare -a stat
{
    unset n
    stat[st_dev     = n++]="long"
    stat[st_ino     = n++]="long"
    stat[st_nlink   = n++]="long"
    stat[st_mode    = n++]="int"
    stat[st_uid     = n++]="int"
    stat[st_gid     = n++]="int"
    stat[             n++]="int"    # Padding
    stat[st_rdev    = n++]="long"
    stat[st_size    = n++]="long"
    stat[st_blksize = n++]="long"
    stat[st_blocks  = n++]="long"
}

# stat is not exported, use xstat instead.
dlcall $RTLD_DEFAULT __xstat 0 "/etc/passwd" $statbuf
unpack $statbuf stat

printf "/etc/passwd\n"
printf "\tuid:  %u\n" ${stat[st_uid]##*:}
printf "\tgid:  %u\n" ${stat[st_gid]##*:}
printf "\tmode: %o\n" ${stat[st_mode]##*:}
printf "\tsize: %u\n" ${stat[st_size]##*:}

dlcall $RTLD_DEFAULT free $statbuf

if test ${stat[st_size]##*:} -eq $(stat -c %s /etc/passwd); then
    echo PASS
    exit 0
fi

echo FAIL
exit 1
