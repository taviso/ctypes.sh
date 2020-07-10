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
$ dlopen libm.so.6
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

* libffi
* bash
* libelf (optional)
* elfutils (optional)
* libdwarf / libdw (optional)


### Fedora

For recent Fedora, this should be enough:

`sudo yum install elfutils-devel dnf-utils`

Now you can use the `debuginfo-install` command to install debugging symbols for automatic structure support.

### Ubuntu

For recent Ubuntu, this should be enough:

`sudo apt install autoconf libltdl-dev libffi-dev libelf-dev elfutils libdw-dev`

If you want to use automatic struct support (recommended), you should also make
you have [ddebs available](https://wiki.ubuntu.com/Debug%20Symbol%20Packages).

## install

`ctypes.sh` can be installed from source like this:

```bash
$ git clone https://github.com/taviso/ctypes.sh.git
$ cd ctypes.sh
$ ./autogen.sh
$ ./configure
$ make
$ [sudo] make install
```

By default `ctypes.sh` is installed into `/usr/local/bin` and
`/usr/local/lib`. You can overload the prefix path by defining the
`PREFIX` environment variable before installing.

```bash
$ PREFIX=$HOME make install
```

## example

```bash
source ctypes.sh
puts () {
  dlcall puts "$@"
  return $?
}

puts "hello, world"
```

## Here is what people have been saying about ctypes.sh:

* "that's disgusting"
* "this has got to stop"
* "you've gone too far with this"
* "is this a joke?"
* "I never knew the c could stand for Cthulhu."

You can read more about ctypes.sh and see it in action on the [Wiki](https://github.com/taviso/ctypes.sh/wiki)
