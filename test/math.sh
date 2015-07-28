#!/bin/bash

source ../ctypes.sh

set -e -x

# load the math library
dlopen libm.so

function verify_result()
{
    if test $(dlcall -n result -r double ${DLHANDLES[libm.so]} ${1} ${2} 2>&1) != ${3}; then
        echo FAIL
        exit 1
    fi
}

verify_result sin double:0 double:0.000000
verify_result sin double:-0 double:-0.000000
verify_result sin double:0.7 double:0.644218
verify_result sin double:inf double:-nan
verify_result sin double:1.57079632679489661923 double:1.000000 # pi/2

echo PASS
