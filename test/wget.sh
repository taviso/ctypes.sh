#!/bin/bash
#
# Simple getaddrinfo() example.
#

source ctypes.sh

declare -r AF_UNSPEC=int:0
declare -r SOCK_STREAM=int:1

struct addrinfo hints
struct addrinfo result

# getaddrinfo requires a struct getaddrinfo **, stored in this array.
declare -a nativeptr=(pointer)

# Request to send
declare hostname="www.google.com"
declare port="80"
declare request=$'GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n'

hints[ai_family]=$AF_UNSPEC
hints[ai_socktype]=$SOCK_STREAM

# Allocate space for a native structure.
sizeof -m hintsptr addrinfo

# Allocate space for a pointer
sizeof -m resultptr long

# Translate hints to native structure.
pack $hintsptr hints

# Call getaddrinfo()
dlcall -r int -n s getaddrinfo string:$hostname string:$port $hintsptr $resultptr

# Check result, and print error if necessary. Note that if you want c-style
# escapes in bash, you need to use $'xxx', not "xxx".
if [[ $s != int:0 ]]; then
    dlcall -r pointer -n gaierror gai_strerror $s
    dlcall printf $'getaddrinfo returned an error, %s\n' $gaierror
    dlcall free $hinstrptr
    dlcall free $resultptr
    exit 1
fi

# Translate the result into bash structure.
unpack $resultptr nativeptr
unpack $nativeptr result

# getaddrinfo returns a linked list, try each one until one works.
while true; do
    # Attempt to connect to this address
    dlcall -r int -n sfd socket ${result[ai_family]} ${result[ai_socktype]} ${result[ai_protocol]}
    dlcall -r int -n ret connect $sfd ${result[ai_addr]} ${result[ai_addrlen]}

    # Check if connect() succeeded
    if [[ $ret == int:0 ]]; then
        break
    fi

    # This is the bash syntax to close a fd (not from ctypes).
    exec {sfd}>&-

    # Check if there is another address to try
    if [[ ${result[ai_next]} == $NULL ]]; then
        break
    fi

    # Move to the next element of list
    unpack ${result[ai_next]} result
done

dlcall freeaddrinfo $nativeptr
dlcall free $hintsptr
dlcall free $resultptr

if [[ $ret != int:0 ]]; then
    echo "unable to connect to any address, giving up..."
    exit 1
fi

# Send a GET request and read a few bytes of response.
dlcall -r pointer -n buf calloc 128 1
dlcall -r int -n ret write $sfd string:"${request}" ${#request}
dlcall -r int -n ret read $sfd $buf 127

# close unused socket
exec {sfd}>&-

# Check if that worked
if [[ $ret != int:-1 ]]; then
    response=$(dlcall puts $buf)

    # Print the response received from server
    echo "$response"

    if [[ ${response:0:15} == "HTTP/1.1 200 OK" ]]; then
        echo PASS
    fi
fi

dlcall free $buf
exit 0
