#!/bin/bash
#
# Use alarm or itimerval to schedule timers.
#

declare -i n=0

if ! source ctypes.sh; then
    echo "ctypes.sh could not be found; make install?"
    exit 1
fi

trap 'printf "PASS %d/4\n" $n; let n++' ALRM

if ! struct itimerval timer; then
    echo "unable to create itimerval structure, missing debuginfo?"
    exit 1
fi

# allocate memory
sizeof -m timerptr itimerval

# setup an interval timer every 1 second
timer[it_interval.tv_sec]=long:1
timer[it_value.tv_sec]=long:1

# export struct to native memory
pack $timerptr timer

# start timer
dlcall setitimer 0 $timerptr $NULL

# wait for the alarms
while ((n != 4)); do
    dlcall pause
done

# disable the timer by setting it to zero.
timer[it_interval.tv_sec]=long:0
timer[it_value.tv_sec]=long:0

# export struct to native memory
pack $timerptr timer

# stop timer
dlcall setitimer 0 $timerptr $NULL

# free memory
dlcall free $timerptr

# Or f you prefer to keep it simple, just use alarm...
dlcall alarm 1

# Wait for the last alarm...
dlcall pause

echo PASS

exit 0
