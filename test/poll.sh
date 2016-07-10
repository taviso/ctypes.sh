#!/bin/bash
#
# This is just an example of using poll(). Naturally you wouldn't use ctypes to
# do something this simple, but managing lots of blocking file descriptors in
# bash is much easier with native system features like poll.
#

source ctypes.sh

declare -ri POLLIN=1
declare -ri POLLPRI=2
declare -ri POLLOUT=4
declare -ri POLLERR=8

struct pollfd fds

# Allocate memory
dlcall -r pointer -n fdsptr malloc $(sizeof pollfd)

# Let's monitor stdin
fds[fd]=$STDIN_FILENO
fds[events]=short:$POLLIN

# convert that bash struct to a native struct
pack $fdsptr fds

while true; do
    echo waiting for file descriptor to be ready...
    dlcall poll $fdsptr 1 -1

    # convert native struct back to bash struct so we can read revents
    unpack $fdsptr fds

    # was the POLLIN (read ready) bit set?
    if ((${fds[revents]##*:} & POLLIN)); then
        echo read will not block...
        read
        echo you will see me immediately!
    fi
done
