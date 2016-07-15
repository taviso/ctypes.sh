#!/bin/bash

source ctypes.sh

set -e

# load the math library
dlopen libm.so || dlopen libm.so.6

function verify_result()
{
    dlcall -n result -r ${3} ${1} ${2}

    if test "$result" != "${3}:${4}"; then
        echo FAIL
        exit 1
    fi
}

verify_result sin double:0 double 0.000000
verify_result sin double:-0 double -0.000000
verify_result sin double:0.7 double 0.644218
verify_result sin double:1.57079632679489661923 double 1.000000 # pi/2

verify_result sin rawdouble:0x1.921fb54442d18p+0 rawdouble 0x1p+0 # pi/2
verify_result sin rawdouble:-0x0p+0 rawdouble -0x0p+0

echo PASS
