#!/bin/bash

source ../ctypes.sh
set -x

dlcall -n hwstr -r pointer $RTLD_DEFAULT strdup "hello, world"

# Check that the string was duplicated
if test "$(dlcall -r int $RTLD_DEFAULT puts $hwstr)" != "hello, world"; then
    echo FAIL
    exit 1
fi

if [ "$(uname -s)" = "Linux" ]; then
    # Check that we can modify it
    dlcall -r pointer $RTLD_DEFAULT strfry $hwstr
else
    dlcall -r pointer $RTLD_DEFAULT memmove $hwstr "a" ulong:1
fi

if test "$(dlcall -r int $RTLD_DEFAULT puts $DLRETVAL)" == "hello, world"; then
    echo FAIL
    exit 1
fi

echo PASS
