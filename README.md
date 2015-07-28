This is ctypes.sh, a foreign function interface for bash.

ctypes.sh is a bash plugin that provides a foreign function interface directly
in your shell. In other words, it allows you to call routines in shared
libraries from within bash.

A (very) simple example will help illustrate:

    $ dlcall $RTLD_NEXT puts "hello, world"
    hello, world

ctypes.sh can extend bash scripts to accomplish tasks that were previously
impossible, or would require external helpers to be written.

Here is what people have been saying about ctypes.sh:

* "that's disgusting"
* "this has got to stop"
* "you've gone too far with this"
* "is this a joke?"
* "wtf"
* "I never knew the c could stand for Cthulu."

You can read more about ctypes.sh and see it in action on the [Wiki](https://github.com/taviso/ctypes.sh/wiki)
