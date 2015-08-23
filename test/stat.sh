#!/bin/bash

source ../ctypes.sh

# Allocate some space for the stat buffer
dlcall -n statbuf -r pointer malloc 1024

# Define the format of struct stat for bash
declare -a stat
{
    unset n
    if [ "$(uname -s)" = "Linux" ]; then
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
    elif [ "$(uname -s)" = "FreeBSD" ]; then
        stat[st_dev     = n++]="uint32"
        stat[st_ino     = n++]="uint32"
        stat[st_mode    = n++]="uint16"
        stat[st_nlink   = n++]="uint16"
        stat[st_uid     = n++]="uint32"
        stat[st_gid     = n++]="uint32"
        stat[st_rdev    = n++]="uint32"

        stat[st_atim_sec= n++]="int64"
        stat[st_atim_ns = n++]="long"
        # Assuming long is 64-bit, no padding.
        stat[st_mtim_sec= n++]="int64"
        stat[st_mtim_ns = n++]="long"
        stat[st_ctim_sec= n++]="int64"
        stat[st_ctim_ns = n++]="long"

        stat[st_size    = n++]="int64"
        stat[st_blocks  = n++]="int64"
        stat[st_blksize = n++]="int32"
    else
        echo "$0 needs porting to $(uname -s)"
        exit 1
    fi
}

# stat is not exported, use xstat instead.
if [ "$(uname -s)" = "Linux" ]; then
    dlcall -r int __xstat 0 "/etc/passwd" $statbuf
else
    dlcall -r int stat "/etc/passwd" $statbuf
fi
unpack $statbuf stat

printf "/etc/passwd\n"
printf "\tuid:  %u\n" ${stat[st_uid]##*:}
printf "\tgid:  %u\n" ${stat[st_gid]##*:}
printf "\tmode: %o\n" ${stat[st_mode]##*:}
printf "\tsize: %u\n" ${stat[st_size]##*:}

dlcall free $statbuf

# Silly incompatibilities.
if [ "$(uname -s)" = "Linux" ]; then
    pwdsize=$(stat -c %s /etc/passwd)
elif [ "$(uname -s)" = "FreeBSD" ]; then
    pwdsize=$(stat -f %z /etc/passwd)
fi

if test ${stat[st_size]##*:} -eq $pwdsize; then
    echo PASS
    exit 0
fi

echo FAIL
exit 1
