#!/bin/bash
source ../ctypes.sh

# Allocate some space for the stat buffer
dlcall -n statbuf -r pointer calloc 1024 1

# Define the format of struct stat for bash
declare -a stat
{
    unset n
    stat[st_dev     = n++]="longlong"
    stat[             n++]="unsigned"  # Padding
    stat[st_ino     = n++]="unsigned"
    stat[st_mode    = n++]="unsigned"
    stat[st_nlink   = n++]="unsigned"
    stat[st_uid     = n++]="unsigned"
    stat[st_gid     = n++]="unsigned"
    stat[             n++]="unsigned"  # Padding
    stat[st_rdev    = n++]="longlong"
    stat[st_size    = n++]="unsigned"
    stat[st_blksize = n++]="unsigned"
    stat[st_blocks  = n++]="unsigned"
}

# stat is not exported, use xstat instead.
dlcall __xstat 3 "/etc/passwd" $statbuf
unpack $statbuf stat

printf "/etc/passwd\n"
printf "\tuid:  %u\n" ${stat[st_uid]##*:}
printf "\tgid:  %u\n" ${stat[st_gid]##*:}
printf "\tmode: %o\n" ${stat[st_mode]##*:}
printf "\tsize: %u\n" ${stat[st_size]##*:}

printf "%#x\n" ${stat[@]##*:}

dlcall free $statbuf

if test ${stat[st_size]##*:} -eq $(stat -c %s /etc/passwd); then
    echo PASS
    exit 0
fi

echo FAIL
exit 1
