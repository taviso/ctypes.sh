#!/bin/bash
#
# Test some different struct types we support.
#

source ctypes.sh

function compare_gdb_size()
{
    gdb -q -ex "file structs.so" -ex "q sizeof(${1}) != ${2}"
}

dlopen ./structs.so

struct nested nested

# verify that nested anonymous and named structures work
if ! compare_gdb_size nested $(sizeof nested)   \
 || test "${nested[a]}"         != int          \
 || test "${nested[.b]}"        != int          \
 || test "${nested[.named.c]}"  != int          \
 || test "${nested[.named..d]}" != int; then
    echo FAIL
    exit 1
fi

struct hasunion hasunion

# verify that unions work, and selecting union members work
if ! compare_gdb_size hasunion $(sizeof hasunion)   \
 || test "${hasunion[a]}"       != int              \
 || test "${hasunion[.h]}"      != uchar            \
 || ! test -z "${hasunion[.i]}"                     \
 || ! test -z "${hasunion[g.f]}"                    \
 || test "${hasunion[g.b]}"     != uchar; then
    echo FAIL
    exit 1
fi

# Try again selecting different members
struct -u g:f,:i hasunion hasunion
if  test "${hasunion[g.f]}"     != double            \
 || test "${hasunion[.i]}"      != ushort            \
 || ! test -z "${hasunion[.h]}"                      \
 || ! test -z "${hasunion[g.b]}"; then
    echo FAIL
    exit 1;
fi

struct manytypes manytypes

# check that different types are working
if ! compare_gdb_size manytypes $(sizeof manytypes)     \
 || test "${manytypes[a]}"         != uchar             \
 || test "${manytypes[b]}"         != ushort            \
 || test "${manytypes[c]}"         != unsigned          \
 || test "${manytypes[d]}"         != ulong             \
 || test "${manytypes[e]}"         != double            \
 || test "${manytypes[f]}"         != float             \
 || test "${manytypes[g]}"         != pointer           \
 || test "${manytypes[h]}"         != pointer; then
    echo FAIL
    exit 1
fi

struct hasarray hasarray

# check that simple structures work
if ! compare_gdb_size hasarray $(sizeof hasarray)   \
 || test "${hasarray[a[0]]}"       != int           \
 || test "${hasarray[a[31]]}"      != int           \
 || ! test -z "${hasarray[a[32]]}"                  \
 || ! test -z "${hasarray[b[0]]}"; then             # not 100% sure this is the right thing to do
    echo FAIL
    exit 1
fi

struct hasenum hasenum

# check that basic enums work
if ! compare_gdb_size hasenum $(sizeof hasenum)     \
 || test "${hasenum[e]}"    != int                  \
 || test "${hasenum[h]}"    != long; then
    echo FAIL
    exit 1
fi

struct -a unnamed_t unnamed

# check that anonymous structures referenced via typedef work
if ! compare_gdb_size unnamed_t $(sizeof -a unnamed_t)  \
 || test "${unnamed[a]}" != int                         \
 || test "${unnamed[b]}" != long; then
    echo FAIL
    exit 1
fi

# these dont work yet, but at least shouldnt crash
struct complexarray complexarray
struct complexunion complexunion
struct bitfields bitfields

echo PASS
exit 0
