#!/bin/bash
#
# Use alarm or itimerval to schedule timers.
#

source ctypes.sh

declare -i n=0

trap 'printf "PASS %d/5\n" $n; let n++' ALRM

struct itimerval timer

# allocate memory
dlcall -r pointer -n timerptr malloc $(sizeof itimerval)

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

# Or f you prefer to keep it simple, just use alarm...
dlcall alarm 1

# Wait for the last alarm...
dlcall pause

exit 0
