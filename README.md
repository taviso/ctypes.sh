This is ctypes.sh, a foreign function interface for bash.

ctypes.sh is a bash plugin that provides a foreign function interface directly
in your shell. In other words, it lets you call routines from shared libraries
in bash.

Perhaps an example might help.

    $ dlopen libc.so.6
    $ dlcall ${DLHANDLES[libc.so.6]} printf "%s%c" "hello" 10
    hello
    $ dlclose ${DLHANDLES[libc.so.6]}

Perhaps you want to call an internal bash routine:

    $ dlcall $RTLD_DEFAULT 
