#!/bin/bash
#
# listen on port 8080 for some data, then dump it to stdout.
#

source ctypes.sh

set -x

declare -r AF_INET=ushort:2
declare -r INADDR_ANY=unsigned:0
declare -r SOCK_STREAM=int:1
declare -r socklen=$(sizeof sockaddr_in)

struct sockaddr_in sockaddr

# set port to network byte order
dlcall -n port -r ushort htons uint16:8080

# generate listen sockaddr
dlcall -n addrbuf -r pointer malloc $socklen

sockaddr[sin_family]=$AF_INET
sockaddr[sin_port]=$port
sockaddr[sin_addr.s_addr]=$INADDR_ANY

pack $addrbuf sockaddr

# listen
dlcall -n sockfd -r int socket $AF_INET $SOCK_STREAM 0
dlcall -r int bind $sockfd $addrbuf $socklen
dlcall -r int listen $sockfd 128
dlcall -n readfd -r int accept $sockfd $NULL $NULL

# remove the type prefix from file descriptors
readfd=${readfd##*:}
sockfd=${sockfd##*:}

# you can use the err function to print useful errors
if ((sockfd == -1 || readfd == -1)); then
    dlcall err 1 "accept failed"
fi

# dump the data received
cat <&${readfd}

# close file descriptors
exec {readfd}>&-
exec {sockfd}>&-
