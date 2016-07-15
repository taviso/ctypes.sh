#!/bin/bash
#
# Test some different struct types we support.
#

source ctypes.sh

set -e

function compare_gdb_size()
{
    gdb -q -ex "file structs.so" -ex "q sizeof(${1}) != ${2}" -ex "q 0" &> /dev/null
}

dlopen ./structs.so

echo "Testing nested anonymous and named structs..."

struct nested nested

if ! compare_gdb_size nested $(sizeof nested)   \
 || test "${nested[a]}"         != int          \
 || test "${nested[.b]}"        != int          \
 || test "${nested[.named.c]}"  != int          \
 || test "${nested[.named..d]}" != int; then
    echo FAIL
    exit 1
else
    echo PASS
fi

echo "Testing unions work, and selecting union members..."

struct hasunion hasunion

if ! compare_gdb_size hasunion $(sizeof hasunion)   \
 || test "${hasunion[a]}"       != int              \
 || test "${hasunion[.h]}"      != uchar            \
 || ! test -z "${hasunion[.i]}"                     \
 || ! test -z "${hasunion[g.f]}"                    \
 || test "${hasunion[g.b]}"     != uchar; then
    echo FAIL
    exit 1
else
    echo PASS 1/2
fi

# Try again selecting different members
struct -u g:f,:i hasunion hasunion
if  test "${hasunion[g.f]}"     != double            \
 || test "${hasunion[.i]}"      != ushort            \
 || ! test -z "${hasunion[.h]}"                      \
 || ! test -z "${hasunion[g.b]}"; then
    echo FAIL
    exit 1;
else
    echo PASS 2/2
fi

echo "Testing structs with many different types..."

struct manytypes manytypes

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
else
    echo PASS
fi

echo "Testing structs with arrays..."

struct hasarray hasarray

if ! compare_gdb_size hasarray $(sizeof hasarray)   \
 || test "${hasarray[a[0]]}"       != int           \
 || test "${hasarray[a[31]]}"      != int           \
 || ! test -z "${hasarray[a[32]]}"                  \
 || ! test -z "${hasarray[b[0]]}"; then             # not 100% sure this is the right thing to do
    echo FAIL
    exit 1
else
    echo PASS
fi

echo "Testing structs with embedded enums..."

struct hasenum hasenum

if ! compare_gdb_size hasenum $(sizeof hasenum)     \
 || test "${hasenum[e]}"    != int                  \
 || test "${hasenum[h]}"    != long; then
    echo FAIL
    exit 1
else
    echo PASS
fi

struct -a unnamed_t unnamed

echo "Check that anonymous structures referenced via typedef work..."

if ! compare_gdb_size unnamed_t $(sizeof -a unnamed_t)  \
 || test "${unnamed[a]}" != int                         \
 || test "${unnamed[b]}" != long; then
    echo FAIL
    exit 1
else
    echo PASS
fi

echo "Check that structs with funky packing work..."

struct mixedpack mixedpack

if ! compare_gdb_size mixedpack $(sizeof mixedpack)     \
 || test "${mixedpack[a]}" != uchar                     \
 || test "${mixedpack[b]}" != unsigned                  \
 || test "${mixedpack[c]}" != uchar                     \
 || test "${mixedpack[d]}" != unsigned; then
    echo FAIL
    exit 1
else
    echo PASS
fi

echo "Testing structs that dont work yet, but shouldnt crash (errors are normal)..."
struct complexarray complexarray || true
struct complexunion complexunion || true
struct bitfields bitfields || true

echo PASS
exit 0
