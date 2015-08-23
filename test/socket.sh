#!/bin/bash
#
# listen on port 8080 for some data, then dump it to stdout.
#

source ../ctypes.sh

declare -r AF_INET=2
declare -r INADDR_ANY=0
declare -r SOCK_STREAM=1

declare -a sockaddr_in
{
    unset n
    sockaddr_in[sin_family  = n++]="uint16"
    sockaddr_in[sin_port    = n++]="uint16"
    sockaddr_in[sin_addr    = n++]="uint32"
    sockaddr_in[sin_zero    = n++]="uint64"
}

set -x

# set port to network byte order
dlcall -n port -r uint16 htons uint16:8080

# generate listen sockaddr
dlcall -n serv_addr -r pointer calloc 1 16

sockaddr_in[sin_family]=uint16:$AF_INET
sockaddr_in[sin_port]=$port
sockaddr_in[sin_addr]=uint32:$INADDR_ANY

pack $serv_addr sockaddr_in

# listen
dlcall -n sockfd -r int socket $AF_INET $SOCK_STREAM 0 
dlcall -r int bind $sockfd $serv_addr 16
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
