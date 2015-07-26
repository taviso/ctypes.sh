#!/bin/bash

source ../ctypes.sh
set -x

dlcall -r pointer $RTLD_DEFAULT malloc 1024

statbuf=$DLRETVAL

declare -a stat
{
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

# stat is usually not exported, use syscall instead.

dlcall $RTLD_DEFAULT syscall 4 "/etc/passwd" $statbuf
unpack $statbuf stat

printf "uid:  %s\n" ${stat[st_uid]}
printf "gid:  %s\n" ${stat[st_gid]}
printf "mode: %s\n" ${stat[st_mode]}
printf "size: %s\n" ${stat[st_size]}

dlcall $RTLD_DEFAULT free $statbuf
