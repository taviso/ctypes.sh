#!/bin/bash
#
# Testing dlopen syntax
#

source ctypes.sh

function failure ()
{
    echo FAIL
    exit 1
}

# discard error messages
exec 2> /dev/null

dlopen _invalid_lib_name_               && failure
dlopen libm.so.6                        || failure
dlopen libm.so.6 _INVALID_FLAG          && failure
dlopen                                  && failure
dlopen libm.so.6 RTLD_GLOBAL RTLD_LAZY  || failure

echo PASS
