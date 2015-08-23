# ctypes.sh

This is `ctypes.sh`, a foreign function interface for bash.

`ctypes.sh` is a bash plugin that provides a foreign function interface directly
in your shell. In other words, it allows you to call routines in shared
libraries from within bash.

A (very) simple example will help illustrate:

```bash
$ dlcall puts "hello, world"
hello, world

# A more complex example, use libm to calculate sin(PI/2)
$ dlopen libm.so
0x172ebf0
$ dlcall -r double sin double:1.57079632679489661923
double:1.000000
```

`ctypes.sh` can extend bash scripts to accomplish tasks that were previously
impossible, or would require external helpers to be written.

`ctypes.sh` makes it possible to use
[GTK+](https://github.com/taviso/ctypes.sh/blob/master/test/gtk.sh) natively in
your shell scripts, or write a [high-performance http daemon](https://github.com/cemeyer/httpd.sh).

See more examples [here](https://github.com/taviso/ctypes.sh/tree/master/test)

## prerequisites

`ctypes.sh` is dependent on the following libraries and programs:

* libffi-dev
* bash

## install

`ctypes.sh` can be installed in several ways. You can use the
[clib](https://github.com/clibs/clib) or
[bpkg](https://github.com/bpkg/bpkg) package manager to install
`ctypes.sh`.

```bash
$ clib install taviso/ctypes.sh
```

```bash
$ bpkg install taviso/ctypes.sh
```

You can also build and install from source:

```bash
$ git clone https://github.com/taviso/ctypes.sh.git
$ cd ctypes.sh
$ ./configure
$ make
$ [sudo] make install
```

By default `ctypes.sh` is installed into `/usr/local/bin` and
`/usr/local/lib`. You can overload the prefix path by defining the
`PREFIX` environment variable before installing.

```bash
$ PREFIX=$HOME clib install taviso/ctypes.sh
```

or

```bash
$ PREFIX=$HOME bpkg install taviso/ctypes.sh
```

or

```bash
$ PREFIX=$HOME make install
```

## example

```bash
source ctypes.sh
puts () {
  dlcall $RTLD_DEFAULT puts "$@"
  return $?
}

puts "hello, world"
```

## Here is what people have been saying about ctypes.sh:

* "that's disgusting"
* "this has got to stop"
* "you've gone too far with this"
* "is this a joke?"
* "I never knew the c could stand for Cthulu."

You can read more about ctypes.sh and see it in action on the [Wiki](https://github.com/taviso/ctypes.sh/wiki)
