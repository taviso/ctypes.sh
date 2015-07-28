function initialize_ctypes_module()
{
    local -a builtins=(
        callback
        dlcall
        dlclose
        dlopen
        dlsym
        pack
        unpack
    )

    enable -f ctypes.so ${builtins[@]} &> /dev/null || {
        # is it possible user doesn't have /usr/local/lib in library search path?
        enable -f /usr/local/lib/ctypes.so ${builtins[@]} || {
            echo "can't find the ctypes.so library, run make install?" 1>&2
        }
    }
}

initialize_ctypes_module && unset initialize_ctypes_module
