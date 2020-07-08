#!/bin/bash

source ctypes.sh

if ! dlopen libcrypto.so &> /dev/null; then
    if ! dlopen libcrypto.so.1.1; then
        echo failed to dlopen openssl
        exit 1
    fi
fi

declare ctx md buf
declare size
declare s=(uint8:{1..20})

# SHA_CTX is a typedef, not a struct, so you should use -a
if ! sizeof -am ctx SHA_CTX; then
    echo FIXME: failed to create SHA_CTX structure
    exit 1
fi

dlcall -n md -r pointer malloc 20
dlcall -n buf -r pointer malloc 1024

dlcall SHA1_Init $ctx

while true; do
    dlcall -n size -r long read int:0 $buf 1024
    if test ${size##*:} -le 0; then
        dlcall free $buf
        break
    fi
    dlcall SHA1_Update $ctx $buf $size
done < /etc/passwd

dlcall SHA1_Final $md $ctx

# convert the md into a bash aray
unpack $md s

# print it in hex
result=$(printf "%02x" ${s[*]##*:})

# compare with real value
if sha1sum --check <(printf "%s  /etc/passwd" "${result}"); then
    echo PASS
    exit 0
else
    echo FAIL
    exit 1
fi
