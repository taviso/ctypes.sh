#!/bin/bash
#
# Demonstrate the use of select with file descriptors.
#
# The standard way to monitor file descriptors in bash is to use read -t x -u
# $fd in a busy loop.
#
# Using ctypes.sh, you can use select natively in your scripts. Combining this
# with sockets allows flexibility and scalability that would otherwise be
# impossible.
#

source ../ctypes.sh

set -x

declare -ri FD_SETSIZE=1024 # Maximum number of file descriptors

declare -a timeval
{
    unset n
    timeval[tv_sec  = n++]="long"
    timeval[tv_usec = n++]="long"
}

declare -ai fd_set
{
    for ((n = 0; n < FD_SETSIZE / 32; n++)); do
        fd_set[n]="0"
    done
}

function FD_CLR () {
    local -n fdset=$1
    local -i index=${2##*:}
    ((fdset[index / 32] &= ~(1 << (index % 32))))
}

function FD_SET () {
    local -n fdset=$1
    local -i index=${2##*:}
    ((fdset[index / 32] |= (1 << (index % 32))))
}

function FD_ISSET () {
    local -n fdset=$1
    local -i index=${2##*:}
    if ((fdset[index / 32] & (1 << (index % 32)))); then
        return 0
    fi
    return 1
}

function FD_ZERO () {
    local -n fdset=$1
    for ((n = 0; n < FD_SETSIZE / 32; n++)); do
        fdset[n]="0"
    done
}

dlcall -r pointer -n readfds malloc $((FD_SETSIZE / 4))

FD_SET fd_set $STDIN_FILENO
pack $readfds fd_set

while true; do
    printf "Waiting for input on stdin...\n"
    dlcall -r int select 1 $readfds $NULL $NULL $NULL
    printf "Ready for input, about to start reading..."
    read -N 4096 -t 1 hello
done

