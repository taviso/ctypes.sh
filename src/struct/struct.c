#include <assert.h>
#include <stdio.h>
#include <dwarf.h>
#include <search.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>
#include <ffi.h>

#include "dwarves.h"
#include "dutil.h"
#include "builtins.h"
#include "variables.h"
#include "arrayfunc.h"
#include "common.h"
#include "bashgetopt.h"
#include "util.h"
#include "types.h"
#include "shell.h"

extern GENERIC_LIST *list_reverse();

// This is just to disable ctf support.
static int debug_fmt_error(struct cus *cus __unused,
                           struct conf_load *conf __unused,
                           const char *filename __unused)
{
    return -1;
}

// Export an unused debug format to disable ctf.
struct debug_fmt_ops ctf__ops = {
    .load_file = debug_fmt_error,
};

// Used to store context inside dwarves callbacks.
struct cookie {
    char             *typename;
    int               result;
    char            **filenames;
    unsigned          nfiles;
    SHELL_VAR        *assoc;
    struct cus       *cus;
    struct conf_load *conf;
};

// Map dwarf basetypes to ctypes prefixes
static const char *prefix_for_basetype(const char *basetype)
{
    static struct {
        const char *basetype;
        const char *prefix;
    } basetypemap[] = {
        { .basetype = "unsigned", .prefix = "unsigned" },
        { .basetype = "signed int", .prefix = "int" },
        { .basetype = "unsigned int", .prefix = "unsigned" },
        { .basetype = "int", .prefix = "int" },
        { .basetype = "short unsigned int", .prefix = "ushort" },
        { .basetype = "signed short", .prefix = "short" },
        { .basetype = "unsigned short", .prefix = "ushort" },
        { .basetype = "short int", .prefix = "short" },
        { .basetype = "char", .prefix = "char" },
        { .basetype = "signed char", .prefix = "char" },
        { .basetype = "unsigned char", .prefix = "uchar" },
        { .basetype = "signed long", .prefix = "long" },
        { .basetype = "long int", .prefix = "long" },
        { .basetype = "signed long", .prefix = "long" },
        { .basetype = "unsigned long", .prefix = "ulong" },
        { .basetype = "long unsigned int", .prefix = "ulong" },
        { .basetype = "bool", .prefix = "byte" },
        { .basetype = "_Bool", .prefix = "byte" },
        { .basetype = "long long unsigned int", .prefix = "uint64" },
        { .basetype = "long long int", .prefix = "int64" },
        { .basetype = "signed long long", .prefix = "int64" },
        { .basetype = "unsigned long long", .prefix = "uint64" },
        { .basetype = "double", .prefix = "double" },
        { .basetype = "double double", .prefix = "longdouble" },
        { .basetype = "single float", .prefix = "float" },
        { .basetype = "float", .prefix = "float" },
        { .basetype = "long double", .prefix = "longdouble" },
        { 0 },
    };

    for (int n = 0; basetypemap[n].basetype; n++) {
        if (strcmp(basetypemap[n].basetype, basetype) == 0)
            return basetypemap[n].prefix;
    }

    builtin_error("couldn't map %s onto a ctypes prefix", basetype);

    return NULL;
};

// This gets called once for every compilation unit, and we're expected to
// search it to see if it contains something we're interested in.
static enum load_steal_kind create_array_stealer(struct cu *cu, struct conf_load *conf_load)
{
    static uint16_t class_id;
    struct tag *tag;
    struct class *class;
    struct class_member *member;
    struct cookie *cookie = conf_load->cookie;
    struct conf_fprintf conf = {0};
    char varname[128] = {0};


    // Check if this compilation unit contains the structname requested.
    if (!(tag = cu__find_struct_by_name(cu, cookie->typename, false, &class_id)))
        return LSK__DELETE;

    class = tag__class(tag);

    // This macro enumerates through each member of the struct.
    type__for_each_data_member(&class->type, member) {
        struct tag *type = cu__type(cu, member->tag.type);

        // Keep calling cu__type() until this is a base type.
        while (tag__is_typedef(type)) {
            if (!(type = cu__type(cu, type->type))) {
                builtin_error("failed to resolve a typedef into a base type");
                goto error;
            }
        }

        // If this is a base type, we're done and can set this member.
        if (type->tag == DW_TAG_base_type) {
            snprintf(varname, sizeof varname, "%s[\"%s\"]",
                                              cookie->assoc->name,
                                              class_member__name(member, cu));

            if (assign_array_element(varname,
                                     prefix_for_basetype(cu__string(cu, tag__base_type(type)->name)),
                                     AV_USEIND) == NULL) {
                builtin_error("error exporting member %s to associative array %s",
                              varname,
                              cookie->assoc->name);
                goto error;
            }
        } else if (type->tag == DW_TAG_array_type) {
            struct array_type *at   = tag__array_type(type);
            struct tag *abtype      = cu__type(cu, type->type);

            // First we need to know the base type of the array.
            while (tag__is_typedef(abtype)) {
                if (!(abtype = cu__type(cu, abtype->type))) {
                    builtin_error("failed to resolve an array typedef into a base type");
                    goto error;
                }
            }

            if (at->dimensions != 1) {
                builtin_error("multi-dimensional arrays are not currently supported");
                goto error;
            }

            // For each element, create an associative array member for it.
            for (int i = 0; i < at->nr_entries[0]; i++) {
                // Generate the index for this member.
                snprintf(varname, sizeof varname, "%s[\"%s[%u]\"]",
                                                   cookie->assoc->name,
                                                   class_member__name(member, cu),
                                                   i);

                // Set it to it's base type.
                if (assign_array_element(varname,
                                         prefix_for_basetype(cu__string(cu, tag__base_type(abtype)->name)),
                                         AV_USEIND) == NULL) {
                    builtin_error("error setting array element member %s", varname);
                    goto error;
                }
            }
        } else {
            builtin_warning("struct: sorry, member %s isn't supported yet!", class_member__name(member, cu));
        }
    }

success:
    // If we reach here, we were able to successfully export the struct.
    cookie->result = EXECUTION_SUCCESS;

error:
    // No need to keep loading.
    return LSK__STOP_LOADING;
}

static int shared_library_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    struct cookie *config = data;

    // If the name is empty, we can't use it.
    if (strlen(info->dlpi_name) == 0)
        return 0;

    // Check if this object defines the structure requested.
    cus__load_file(config->cus, config->conf, info->dlpi_name);

    // If that succeeded, we can exit dl_iterate_phdr early.
    if (config->result == EXECUTION_SUCCESS) {
        return 1;
    }

    return 0;
}

static int generate_standard_struct(WORD_LIST *list)
{
    HASH_TABLE *hashtable;
    BUCKET_CONTENTS *bucket;
    struct conf_load conf_load = {
        .steal                  = create_array_stealer,
        .format_path            = NULL,
        .extra_dbg_info         = false,
        .fixup_silly_bitfields  = true,
        .get_addr_info          = false,
    };
    struct cookie config = {
        .result     = EXECUTION_FAILURE,
        .assoc      = NULL,
        .cus        = cus__new(),
        .conf       = &conf_load,
    };

    // Verify we have two parameters.
    if (!list || !list->next) {
        builtin_usage();
        return EXECUTION_FAILURE;
    }

    // Create the array used to save the result.
    config.assoc     = make_new_assoc_variable(list->next->word->word);
    config.typename  = list->word->word;
    conf_load.cookie = &config;
    hashtable        = assoc_create(1);

    // Throw away the default hash table.
    assoc_dispose((void *) config.assoc->value);

    // Replace it with our own hash table with just one bucket.
    config.assoc->value = (char *) hashtable;

    dwarves__init(0);

    dl_iterate_phdr(shared_library_callback, &config);

    if (config.result != EXECUTION_SUCCESS) {
        builtin_warning("structure %s could not be parsed perfectly, may be incomplete", config.typename);
    }

    // The members were appended in reverse, so try to fix.
    bucket = REVERSE_LIST(hashtable->bucket_array[0], BUCKET_CONTENTS *);

    // Install the new list head.
    hashtable->bucket_array[0] = bucket;

    cus__delete(config.cus);
    dwarves__exit();
    return config.result;
}

static int sizeof_standard_struct(WORD_LIST *list)
{
    builtin_error("not implemented yet");
    return EXECUTION_FAILURE;
}

static char *struct_usage[] = {
    "",
    "Automatically define a standard structure.",
    "",
    "The struct command searches for the specified structure definition and",
    "attempts to create a matching bash array for use with the pack and",
    "unpack commands. This simplifies the process of creating complicated",
    "structures, but requires compiler debug information.",
    "",
    "If the struct command fails, it's possible that the debugging",
    "information required to recreate types is missing. Try these steps:",
    "",
    "   * On Fedora, RedHat or CentOS, try debuginfo-install <library>",
    "   * On Debian or Ubuntu, try apt-get install <library>-dbg",
    "   * On FreeBSD, enable WITH_DEBUG_FILES in src.conf and recompile",
    "   * If this is your own library, don't use strip",
    "",
    "If none of these are possible, you may have to define the structure",
    "manually, see the documentation for details.",
    "",
    "Example:",
    "",
    "   # create a bash version of the stat structure",
    "   struct stat passwd"
    "",
    "   # allocate some space for native stat buffer",
    "   dlcall -n statbuf -r pointer malloc $(sizeof stat)",
    "",
    "   # call stat()",
    "   dlcall -r int __xstat 0 \"/etc/passwd\" $statbuf # Linux",
    "   dlcall -r int stat \"/etc/passwd\" $statbuf # FreeBSD",
    "",
    "   # parse the native struct into bash struct",
    "   unpack $statbuf passwd",
    "",
    "   # access the structure using bash syntax",
    "   printf \"/etc/passwd\\n\"",
    "   printf \"\\tuid:  %u\\n\" ${passwd[st_uid]##*:}",
    "   printf \"\\tgid:  %u\\n\" ${passwd[st_gid]##*:}",
    "   printf \"\\tmode: %o\\n\" ${passwd[st_mode]##*:}",
    "   printf \"\\tsize: %u\\n\" ${passwd[st_size]##*:}",
    "",
    NULL,
};

static char *sizeof_usage[] = {
    "",
    "Calculate the size of a standard structure.",
    "",
    "Print the size of bytes of the specified structure. See the struct command",
    "for more information",
    NULL,
};

struct builtin __attribute__((visibility("default"))) struct_struct = {
    .name       = "struct",
    .function   = generate_standard_struct,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = struct_usage,
    .short_doc  = "struct [structname] [varname]",
    .handle     = NULL,
};

struct builtin __attribute__((visibility("default"))) sizeof_struct = {
    .name       = "sizeof",
    .function   = sizeof_standard_struct,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = sizeof_usage,
    .short_doc  = "sizeof [structname]",
    .handle     = NULL,
};
