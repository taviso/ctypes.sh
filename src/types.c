#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <ffi.h>
#include <inttypes.h>

#include "builtins.h"
#include "variables.h"
#include "arrayfunc.h"
#include "common.h"
#include "bashgetopt.h"
#include "types.h"
#include "util.h"

#ifndef __GLIBC__
#include <sys/param.h>
#define strndupa(s, n) ({                               \
    const char *__s = (s);                              \
    size_t __n = (n);                                   \
    char *__r;                                          \
    __n = MIN(__n, strlen(__s));                        \
    __r = alloca(__n + 1);                              \
    memcpy(__r, __s, __n);                              \
    __r[__n] = '\0';                                    \
    __r;                                                \
})
#endif


// Given an appropriate format and an ffi_type, create a prefixed type from
// value and store in *result, which should be freed by the caller.
char * encode_primitive_type(const char *format, ffi_type *type, void *value)
{
    char *result;

    switch (type->size) {
        case  1: asprintf(&result, format, *(uint8_t  *) value); break;
        case  2: asprintf(&result, format, *(uint16_t *) value); break;
        case  4: asprintf(&result, format, *(uint32_t *) value,  *(float *) value); break;
        case  8: asprintf(&result, format, *(uint64_t *) value, *(double *) value); break;
        case 16: asprintf(&result, format, *(long double *) value); break;
        default:
            builtin_error("cannot handle size %lu", type->size);
            return NULL;
    }

    return result;
}


bool decode_primitive_type(const char *parameter, void **value, ffi_type **type)
{
    const char *prefix;

    prefix  = NULL;
    *value  = NULL;
    *type   = NULL;

    // If a colon exists, then everything before it is a type
    if (strchr(parameter, ':')) {
        // Extract the two components.
        prefix    = strndupa(parameter, strchr(parameter, ':') - parameter);
        parameter = strchr(parameter, ':') + 1;
    } else {
        intmax_t n;
        char *string;

        // No type was specified, so there are only two possibilities,
        // If this is a legal number, then it's an int. Otherwise, this is a
        // string.
        if (check_parse_long(parameter, &n)) {
            *type   = &ffi_type_sint;
            *value  = malloc(ffi_type_sint.size);

            memcpy(*value, &n, ffi_type_sint.size);
            return true;
        }

        // This must be a string.
        *type   = &ffi_type_pointer;
        *value  = malloc(ffi_type_pointer.size);
        string  = strdup(parameter);

        memcpy(*value, &string, ffi_type_pointer.size);
        return true;
    }

    if (decode_type_prefix(prefix, parameter, type, value, NULL) != true) {
        builtin_warning("parameter decoding failed");
        return false;
    }

    return true;
}

bool decode_type_prefix(const char *prefix, const char *value, ffi_type **type, void **result, char **pformat)
{
    static struct {
        char     *prefix;
        ffi_type *type;
        char     *sformat;
        char     *pformat;
    } types[] = {
        { "uint8", &ffi_type_uint8, "%" SCNu8, "uint8:%" PRIu8 },
        { "byte", &ffi_type_uint8, "%" SCNu8, "byte:%" PRIu8 },
        { "int8", &ffi_type_sint8, "%" SCNd8, "int8:%" PRId8 },
        { "uint16", &ffi_type_uint16, "%" SCNu16, "uint16:%" PRIu16 },
        { "int16", &ffi_type_sint16, "%" SCNd16, "int16:%" PRId16 },
        { "uint32", &ffi_type_uint32, "%" SCNu32, "uint32:%" PRIu32 },
        { "int32", &ffi_type_sint32, "%" SCNd32, "int32:%" PRId32 },
        { "uint64", &ffi_type_uint64, "%" SCNu64, "uint64:%" PRIu64 },
        { "int64", &ffi_type_sint64, "%" SCNd64, "int64:%" PRId64 },
        { "float", &ffi_type_float, "%f", "float:%f" },
        { "double", &ffi_type_double, "%lf", "double:%lf" },
        { "rawfloat", &ffi_type_float, "%a", "rawfloat:%a" },
        { "rawdouble", &ffi_type_double, "%la", "rawdouble:%la" },
        { "char", &ffi_type_schar, "%c", "char:%c" },
        { "uchar", &ffi_type_uchar, "%c", "uchar:%c" },
        { "ushort", &ffi_type_ushort, "%hu", "ushort:%hu" },
        { "short", &ffi_type_sshort, "%hd", "short:%hd", },
        { "unsigned", &ffi_type_uint, "%u", "unsigned:%u" },
        { "int", &ffi_type_sint, "%d", "int:%d" },
        { "bool", &ffi_type_sint, "%d", "bool:%d" },
        { "boolean", &ffi_type_sint, "%d", "boolean:%d" },
        { "ulong", &ffi_type_ulong, "%lu", "ulong:%lu" },
        { "long", &ffi_type_slong, "%ld", "long:%ld" },
        { "longlong", &ffi_type_uint64, "%lld", "longlong:%lld" },
        { "longdouble", &ffi_type_longdouble, "%llg", "longdouble:%llg" },
        { "rawlongdouble", &ffi_type_longdouble, "%lla", "rawlongdouble:%lla" },
        { "pointer", &ffi_type_pointer, "%" SCNxPTR, "pointer:%#" PRIxPTR },
        { "string", &ffi_type_pointer, NULL, "string:%s" },
        { "void", &ffi_type_void, "", "" },
        { 0 },
    };

    for (int i = 0; types[i].prefix; i++) {
        if (strcmp(types[i].prefix, prefix) == 0) {
            // Prefix matched type, return information user requested.
            if (type) {
                *type = types[i].type;
            }

            if (pformat) {
                *pformat = types[i].pformat;
            }

            // Caller wants us to decode it, lets go ahead.
            if (result) {
                *result = malloc(types[i].type->size);

                if (types[i].sformat == NULL) {
                    char *strmem;

                    strmem = strdup(value);
                    if (strmem == NULL) {
                        builtin_warning("failed to parse %s as a string: no memory",
                            value);
                        free(*result);
                        return false;
                    }

                    **(char ***)result = strmem;
                } else if (sscanf(value, types[i].sformat, *result) != 1) {
                    builtin_warning("failed to parse %s as a %s", value, prefix);
                    free(*result);
                    return false;
                }
            }
            return true;
        }
    }

    builtin_warning("unrecognised type prefix %s", prefix);
    return false;
}
