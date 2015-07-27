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

    "that's disgusting"
    "this has got to stop"
    "you've gone too far with this"
    "is this a joke?"
    "wtf"

I'll introduce the basic features with some more examples, these are not
intended to demonstrate something that was not possible without ctypes, simply
to illustrate usage with familiar examples.



FAQ:

* Q: Why doesn't this work as expected?
```
    $ dlcall $RTLD_DEFAULT printf "%s\n" "Hello, World"
    Hello, World\n
```

* A: Bash strings are not C string literals. If you want C-like
  escape sequences you can do something like this:

```
  $ dlcall $RTLD_DEFAULT printf $'%s\n' "Hello, World"
  Hello, World
```
