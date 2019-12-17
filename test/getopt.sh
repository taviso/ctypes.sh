#!/bin/bash
#

if ! source ctypes.sh; then
    echo "please install ctypes.sh"
    exit 1
fi

# bash doesnt support multi-dimensional arrays, but you can encode them as
# strings and evaluate them at runtime with `eval`
declare -a long_options=(
    "opt[name]=string:add     opt[has_arg]=int:1"
    "opt[name]=string:append  opt[has_arg]=int:0"
    "opt[name]=string:delete  opt[has_arg]=int:1"
    "opt[name]=string:verbose opt[has_arg]=int:0"
    "opt[name]=string:create  opt[has_arg]=int:1"
    "opt[name]=string:file    opt[has_arg]=int:1"
    "opt[name]=$NULL          opt[has_arg]=int:0"
)

function native_getopt_long()
{
    struct option opt

    # Translate parameters into an argument vector.
    declare -a argv=(string:${0} ${*/#/string:})
    declare -a index=(int)

    sizeof -A 1 -m option_index int
    sizeof -A ${#long_options[@]} -m optptr option
    sizeof -A ${#argv[@]} -m argptr pointer

    pack $argptr argv

    for ((i = 0; i < ${#long_options[*]}; i++)); do
        eval ${long_options[i]}
        pack $(sizeof -M $i option $optptr) opt
    done

    while true; do
        dlcall -r int -n c getopt_long ${#argv[@]} $argptr "" $optptr $option_index
        dlsym -n optarg -d pointer optarg

        case $c in
            int:0)  unpack $option_index index
                    eval ${long_options[${index##*:}]}

                    echo you specified ${opt[name]}

                    if test $optarg != $NULL; then
                        echo -n parameter:
                        dlcall puts $optarg
                    fi
                    ;;
            int:-1) break
                    ;;
        esac
    done

    dlcall free $optptr
    dlcall free $argptr
    dlcall free $option_index
}

native_getopt_long --add=foo --create bar --verbose

exit 0

