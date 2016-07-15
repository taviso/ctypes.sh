#!/bin/bash

source ctypes.sh

declare -i sortsize=128     # size of array
declare -a values           # array of values
set -e

# int compare(const void *, const void *)
function compare {
    local -a x=(int)
    local -a y=(int)
    local -a result

    # extract the parameters
    unpack $2 x
    unpack $3 y

    # remove the prefix
    x=${x##*:}
    y=${y##*:}

    # calculate result
    result=(int:$((x - y)))

    # return result to caller
    pack $1 result

    return
}

# Generate a function pointer to compare that can be called from native code.
callback -n compare compare int pointer pointer

# Generate an array of random values
for ((i = 0; i < sortsize; i++)); do
    values+=(int:$RANDOM)
done

# Allocate space for integers
dlcall -n buffer -r pointer malloc $((sortsize * 4))

# Pack our random array into that native array
pack $buffer values

# Now qsort can sort them
dlcall qsort $buffer long:$sortsize long:4 $compare

# Unpack the sorted array back into a bash array
unpack $buffer values

# Verify they're sorted
if ! sort --check --numeric <(IFS=$'\n'; echo "${values[*]##*:}"); then
    echo FAIL
    exit 1
fi

echo PASS
