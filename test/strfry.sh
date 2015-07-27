#!/bin/bash

source ../ctypes.sh
set -x

dlopen libc.so.6

dlcall -r pointer ${DLHANDLES[libc.so.6]} strdup "hello, world"

# Check that the string was duplicated
if test "$(dlcall -r int ${DLHANDLES[libc.so.6]} puts $DLRETVAL)" != "hello, world"; then
    echo FAIL
fi

# Check that we can modify it
dlcall -r pointer ${DLHANDLES[libc.so.6]} strfry "hello, world"

if test "$(dlcall -r int ${DLHANDLES[libc.so.6]} puts $DLRETVAL)" == "hello, world"; then
    echo FAIL
fi

echo PASS
