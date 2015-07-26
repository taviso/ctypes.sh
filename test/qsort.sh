#!/bin/bash

source ../ctypes.sh
set -x

function compare() {
    declare -a x=(uint8) y=(uint8)
    echo I am $FUNCNAME
    echo Args: $@
    unpack $1 x
    unpack $2 y

    x=${x//uint8:/}
    y=${y//uint8:/}

    if   ((x  > y)); then
        return 1
    elif ((x == y)); then
        return 0
    else
        return -1
    fi
}

callback compare pointer pointer; compare=$DLRETVAL

# allocate 8 bytes
dlcall -r pointer $RTLD_DEFAULT malloc 8
dlcall -r pointer $RTLD_DEFAULT memset $DLRETVAL 0x41 8

dlcall $RTLD_DEFAULT qsort $DLRETVAL long:8 long:1 $compare
