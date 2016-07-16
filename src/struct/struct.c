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

#define MAX_ELEMENT_SIZE 128    // Maximum length of array_name[element_name]

static int select_union_string(char *unionstr, const char *unionname, char *membername, size_t maxlen);

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
    char *typename;
    int  result;
    char **filenames;
    unsigned nfiles;
    SHELL_VAR *assoc;
    struct cus *cus;
    struct conf_load *conf;
    size_t size;
    char *unionstr;
    bool anonymous;
};

// Map dwarf basetypes to ctypes prefixes
static char *prefix_for_basetype(const char *basetype, size_t *size)
{
    static struct {
        char *basetype;
        char *prefix;
        size_t size;
    } basetypemap[] = {
        { "unsigned", "unsigned", sizeof(unsigned) },
        { "signed int", "int", sizeof(signed int) },
        { "unsigned int", "unsigned", sizeof(unsigned int) },
        { "int", "int", sizeof(int) },
        { "short unsigned int", "ushort", sizeof(short unsigned int) },
        { "signed short", "short", sizeof(signed short) },
        { "unsigned short", "ushort", sizeof(unsigned short) },
        { "short int", "short", sizeof(short int) },
        { "char", "char", sizeof(char) },
        { "signed char", "char", sizeof(signed char) },
        { "unsigned char", "uchar", sizeof(unsigned char) },
        { "signed long", "long", sizeof(long) },
        { "long int", "long", sizeof(long int) },
        { "signed long", "long", sizeof(signed long) },
        { "unsigned long", "ulong", sizeof(unsigned long) },
        { "long unsigned int", "ulong", sizeof(long unsigned int) },
        { "bool", "byte", sizeof(bool) },
        { "long long unsigned int", "uint64", sizeof(long long unsigned int) },
        { "long long int", "int64", sizeof(long long int) },
        { "signed long long", "int64", sizeof(signed long long) },
        { "unsigned long long", "uint64", sizeof(unsigned long long) },
        { "double", "double", sizeof(double) },
        { "float", "float", sizeof(float) },
        { "long double", "longdouble", sizeof(long double) },
        { "long", "long", sizeof(long) },
        { "pointer", "pointer", sizeof(void *) },
        { "byte", "byte", sizeof(char) },
        { 0 },
    };

    for (int n = 0; basetypemap[n].basetype; n++) {
        if (strcmp(basetypemap[n].basetype, basetype) == 0) {
            if (size) *size = basetypemap[n].size;
            return basetypemap[n].prefix;
        }
    }

    return NULL;
};

int insert_struct_padding(struct cu *cu, struct class_member *member, struct cookie *cookie, const char *basename)
{
    char varname[MAX_ELEMENT_SIZE] = {0};
    size_t hole = member->hole;
    const char *padtype;
    unsigned count = 0;

    while (hole) {
        // We need to apply some padding
        snprintf(varname, sizeof varname, "%s[\"%s%s.__pad%u\"]",
                                          cookie->assoc->name,
                                          basename,
                                          class_member__name(member, cu),
                                          count++);

        // Find the biggest type we can fit, and adjust remaining hole
        // accordingly.
        switch (hole % 8) {
            case 7: padtype = "uint32"; hole -= 4; break;
            case 6: padtype = "uint32"; hole -= 4; break;
            case 5: padtype = "uint32"; hole -= 4; break;
            case 4: padtype = "uint32"; hole -= 4; break;
            case 3: padtype = "uint16"; hole -= 2; break;
            case 2: padtype = "uint16"; hole -= 2; break;
            case 1: padtype = "uint8";  hole -= 1; break;
            case 0: padtype = "uint64"; hole -= 8; break;
        }

        if (assign_array_element(varname, (char *)(padtype), AV_USEIND) == NULL) {
            builtin_error("error exporting %s", varname);
            return -1;
        }
    }

    return 0;
}

// This worker routine recursively decodes structures. This is necessary
// because a structure can itself contain a structure.
int parse_class_worker(struct cu *cu, struct class *class, struct cookie *cookie, char *basename)
{
    struct class_member *member;
    struct class_member *unionmember;
    char varname[MAX_ELEMENT_SIZE] = {0};

    // First we need to find "holes", compiler padding between members.
    class__find_holes(class);

    // This macro iterates over every member in the class. Each member's type
    // needs to be resolved, which can get complicated if it's another struct
    // or a union for example.
    type__for_each_data_member(&class->type, member) {
        struct tag *type = cu__type(cu, member->tag.type);
        const char *membername = class_member__name(member, cu);

        // If this member is anonymous it may not have a name.
        membername = membername ? membername : "";

        // If this is a base type (int, short, etc), but typedef'd to a
        // non-base type (e.g. size_t, uint8_t) then we can just keep resolving
        // typedefs until we reach the base type.
        if (tag__is_typedef(type)) {
            if (!(type = tag__follow_typedef(type, cu))) {
                builtin_error("failed to resolve a typedef, debug information incomplete");
                goto error;
            }
        }

        // If we're lucky, this is a simple type, we're done.
        if (type->tag == DW_TAG_base_type || type->tag == DW_TAG_pointer_type) {
            // Convert this type from a dwarf type into a ffi type.
            const char *typename = type->tag == DW_TAG_base_type
                                 ? prefix_for_basetype(cu__string(cu, tag__base_type(type)->name), NULL)
                                 : "pointer";


            // Generate the array element name we'll be using.
            snprintf(varname, sizeof varname, "%s[\"%s%s\"]",
                                              cookie->assoc->name,
                                              basename,
                                              membername);

            // Assign it the correct type.
            if (assign_array_element(varname, (char *) typename, AV_USEIND) == NULL) {
                builtin_error("error exporting %s", varname);
                goto error;
            }

            // Compensate for any structure padding.
            if (insert_struct_padding(cu, member, cookie, basename) != 0) {
                builtin_error("error appending struct padding to %s", varname);
                goto error;
            }
        } else if (type->tag == DW_TAG_array_type) {
            struct array_type *at   = tag__array_type(type);
            struct tag *abtype      = cu__type(cu, type->type);

            // First we need to know the base type of the array.
            if (tag__is_typedef(abtype)) {
                if (!(abtype = tag__follow_typedef(abtype, cu))) {
                    builtin_error("failed to resolve an array typedef into a base type");
                    goto error;
                }
            }

            if (at->dimensions != 1) {
                builtin_error("multi-dimensional arrays are not currently supported");
                goto error;
            }

            if (abtype->tag != DW_TAG_base_type && abtype->tag != DW_TAG_pointer_type) {
                builtin_error("arrays of complex types (e.g. structs) are not currently supported");
                goto error;
            }

            // For each element, create an associative array member for it.
            for (int i = 0; i < at->nr_entries[0]; i++) {
                // Convert this type from a dwarf type into a ffi type.
                const char *typename = abtype->tag == DW_TAG_base_type
                                     ? prefix_for_basetype(cu__string(cu, tag__base_type(abtype)->name), NULL)
                                     : "pointer";

                // Generate the index for this member.
                snprintf(varname, sizeof varname, "%s[\"%s%s[%u]\"]",
                                                   cookie->assoc->name,
                                                   basename,
                                                   membername,
                                                   i);

                // Set it to it's base type.
                if (assign_array_element(varname, (char *) typename, AV_USEIND) == NULL) {
                    builtin_error("error setting array element member %s", varname);
                    goto error;
                }
            }

            // Compensate for any structure padding.
            if (insert_struct_padding(cu, member, cookie, basename) != 0) {
                builtin_error("error appending struct padding to %s", varname);
                goto error;
            }
        } else if (type->tag == DW_TAG_structure_type) {
            char *newbase;

            // We handle nested structures recursively using a basename, so
            // that the name of the nested structure is appended. e.g.
            // root.nested.foo.bar
            newbase = alloca(strlen(basename)
                           + strlen(membername)
                           + 1
                           + 1);

            sprintf(newbase, "%s%s.", basename, membername);

            // This member is another structure, we need to handle it recursively.
            if (parse_class_worker(cu, tag__class(type), cookie, newbase) != EXECUTION_SUCCESS)
                goto error;

            // Compensate for any structure padding.
            if (insert_struct_padding(cu, member, cookie, basename) != 0) {
                builtin_error("error appending struct padding to %s", varname);
                goto error;
            }
        } else if (type->tag == DW_TAG_union_type) {
            char fullname[MAX_ELEMENT_SIZE] = {0};
            char selectedmember[MAX_ELEMENT_SIZE] = {0};

            // Resolve the full name of this union, so we get
            // struct.union, or struct. if it's an anonymous union
            snprintf(fullname, sizeof fullname, "%s%s", basename, membername);

            // Check if user requested a specific member for this union.
            select_union_string(cookie->unionstr, fullname, selectedmember, sizeof(selectedmember));

            type__for_each_member(&(tag__class(type)->type), unionmember) {
                struct tag *uniontype = cu__type(cu, unionmember->tag.type);

                if (*selectedmember && strcmp(selectedmember, class_member__name(unionmember, cu)) != 0)
                    continue;

                // First we need to know the base type of the member.
                if (tag__is_typedef(uniontype)) {
                    if (!(uniontype = tag__follow_typedef(uniontype, cu))) {
                        builtin_error("failed to resolve an arrunion typedef into a base type");
                        goto error;
                    }
                }

                if (uniontype->tag != DW_TAG_base_type) {
                    builtin_error("unions of complex types (e.g. structures) are not currently supported");
                    goto error;
                }

                // Generate the index for this member.
                snprintf(varname, sizeof varname, "%s[\"%s.%s\"]",
                                                   cookie->assoc->name,
                                                   fullname,
                                                   class_member__name(unionmember, cu));

                // Set it to it's base type.
                if (assign_array_element(varname,
                                         prefix_for_basetype(cu__string(cu, tag__base_type(uniontype)->name), NULL),
                                         AV_USEIND) == NULL) {
                    builtin_error("error setting element member %s", varname);
                    goto error;
                }

                // If this type is smaller than the member type, presumably we need to add padding?
                if (member->byte_size < unionmember->byte_size) {
                    member->hole += member->byte_size - unionmember->byte_size;
                }

                // Compensate for any structure padding.
                if (insert_struct_padding(cu, member, cookie, basename) != 0) {
                    builtin_error("error appending padding to %s", varname);
                    goto error;
                }

                // Member found.
                goto unionfound;
            }

            builtin_error("requested unionmember not found, check syntax");
            goto error;
unionfound:
            continue;
        } else if (type->tag == DW_TAG_enumeration_type) {
            const char *typename;

            // In general, an enum is an int or a long, depending on the
            // maximum member value. If it's something else, we don't handle it
            // for now.
            switch (member->byte_size) {
                case 4: typename = "int"; break;
                case 8: typename = "long"; break;
                default:
                    builtin_error("%s is an unsupported enumeration type, size %lu",
                                  membername,
                                  member->byte_size);
                    goto error;
            }

            // Generate the array element name we'll be using.
            snprintf(varname, sizeof varname, "%s[\"%s%s\"]",
                                              cookie->assoc->name,
                                              basename,
                                              membername);

            // Assign it the correct type.
            if (assign_array_element(varname, (char *) typename, AV_USEIND) == NULL) {
                builtin_error("error exporting %s", varname);
                goto error;
            }

            // Compensate for any structure padding.
            if (insert_struct_padding(cu, member, cookie, basename) != 0) {
                builtin_error("error appending struct padding to %s", varname);
                goto error;
            }
        } else {
            builtin_warning("sorry, member %s is a %s, not supported yet!",
                            membername,
                            dwarf_tag_name(type->tag));
            goto error;
        }
    }

success:
    return EXECUTION_SUCCESS;

error:
    return EXECUTION_FAILURE;
}

struct tag *find_anon_struct_typedef(struct cu *cu, const char *typename)
{
    static uint16_t class_id;
    struct tag *tag;

    cu__for_each_type(cu, class_id, tag) {
        struct type *type = tag__type(tag);
        const char *tname = NULL;

        if (!tag__is_typedef(tag) || !(tname = type__name(type, cu)))
            continue;

        // This is a named typedef, check for match.
        if (strcmp(tname, typename) == 0) {
            tag = tag__follow_typedef(tag, cu);

            if (tag__is_struct(tag))
                return tag;

            builtin_warning("found a matching typedef, but it was not a struct");
        }
    }

    return NULL;
}

// This gets called once for every compilation unit, and we're expected to
// search it to see if it contains something we're interested in.
static enum load_steal_kind create_array_stealer(struct cu *cu, struct conf_load *conf_load)
{
    static uint16_t class_id;
    struct tag *tag;
    struct cookie *cookie = conf_load->cookie;
    char *path;

    // Check if this compilation unit contains the structname requested.
    if (cookie->anonymous) {
        if (!(tag = find_anon_struct_typedef(cu, cookie->typename)))
            return LSK__DELETE;
    } else {
        if (!(tag = cu__find_struct_by_name(cu, cookie->typename, false, &class_id)))
            return LSK__DELETE;
    }

    // Found the class, attempt to parse it into a ctypes array.
    if (parse_class_worker(cu, tag__class(tag), cookie, "") == EXECUTION_SUCCESS)
        cookie->result = EXECUTION_SUCCESS;

    // Record the size.
    cookie->size = class__size(tag__class(tag));

    return LSK__STOP_LOADING;
}

// This gets called once for every compilation unit, and we're expected to
// search it to see if it contains something we're interested in.
static enum load_steal_kind find_sizeof_stealer(struct cu *cu, struct conf_load *conf_load)
{
    static uint16_t class_id;
    struct tag *tag;
    struct cookie *cookie = conf_load->cookie;

    // Check if this compilation unit contains the structname requested.
    if (cookie->anonymous) {
        if (!(tag = find_anon_struct_typedef(cu, cookie->typename)))
            return LSK__DELETE;
    } else {
        if (!(tag = cu__find_struct_by_name(cu, cookie->typename, false, &class_id)))
            return LSK__DELETE;
    }

    cookie->size = class__size(tag__class(tag));
    cookie->result = EXECUTION_SUCCESS;

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

static int select_union_string(char *unionstr, const char *unionname, char *membername, size_t maxlen)
{
    char *saveptr;
    char *token;
    char *member;
    char *currtok;
    char *localstr;

    // Verify we have sane parameters.
    if (!unionstr || !unionname || (!membername && maxlen))
        return -1;

    // Create a local copy of unionstring we can modify.
    localstr = strdupa(unionstr);

    // The input string is like "foo.bar:baz,blah.foo:xyz"
    while (token = strtok_r(localstr, ",", &saveptr)) {
        localstr = NULL;
        currtok  = strdupa(token);
        member   = strrchr(currtok, ':');

        // Now member should be ':baz', and token is still 'foo.bar:baz'
        if (member == NULL) {
            builtin_warning("could not parse union string %s", token);
            continue;
        }

        // Now member is the union member 'baz', and token is 'foo.bar'.
        *member++ = '\0';

        // Check if this is the union requested
        if (strcmp(unionname, currtok) == 0) {
            strncpy(membername, member, maxlen);
            return 0;
        }
    }

    return -1;
}

static int generate_standard_struct(WORD_LIST *list)
{
    int opt;
    HASH_TABLE *hashtable;
    BUCKET_CONTENTS *bucket;
    char *allocvar;
    char allocval[128];
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
        .unionstr   = NULL,
        .anonymous  = false,
        .size       = 0,
    };

    reset_internal_getopt();

    // Name of variable to store optional allocated pointer with -m.
    allocvar = NULL;

    while ((opt = internal_getopt(list, "au:m:")) != -1) {
        switch (opt) {
            case 'u':
                config.unionstr = list_optarg;
                break;
            case 'a':
                config.anonymous = true;
                break;
            case 'm':
                allocvar = list_optarg;
                break;
            default:
                builtin_usage();
                return EX_USAGE;
        }
    }

    // Skip past any options.
    if ((list = loptend) == NULL) {
        builtin_usage();
        return 1;
    }

    // Verify we have two parameters left.
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
        builtin_warning("%s could not be found; check `help struct` for more",
                        config.typename);
        goto cleanup;
    } 

    // The members were appended in reverse, so try to fix.
    bucket = REVERSE_LIST(hashtable->bucket_array[0], BUCKET_CONTENTS *);

    // Install the new list head.
    hashtable->bucket_array[0] = bucket;

    if (allocvar) {
        // NOTE: This is not a leak.
        snprintf(allocval, sizeof allocval, "pointer:%p", calloc(1, config.size));
        bind_variable(allocvar, allocval, 0);
    }

cleanup:
    cus__delete(config.cus);
    dwarves__exit();
    return config.result;
}

static int sizeof_standard_struct(WORD_LIST *list)
{
    int opt;
    char *allocvar;
    char allocval[128];
    struct conf_load conf_load = {
        .steal                  = find_sizeof_stealer,
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
        .size       = 0,
        .anonymous  = false,
    };

    reset_internal_getopt();

    // Name of variable to store optional allocated pointer with -m.
    allocvar = NULL;

    while ((opt = internal_getopt(list, "am:")) != -1) {
        switch (opt) {
            case 'a':
                config.anonymous = true;
                break;
            case 'm':
                allocvar = list_optarg;
                break;
            default:
                builtin_usage();
                return EX_USAGE;
        }
    }

    // Skip past any options.
    if ((list = loptend) == NULL) {
        builtin_usage();
        return 1;
    }

    // Verify we have a parameters.
    if (!list) {
        builtin_usage();
        return EXECUTION_FAILURE;
    }

    // I use the cookie parameter to pass configuration data.
    conf_load.cookie = &config;
    config.typename  = list->word->word;

    // Check if user is asking about a simple type before we do anything
    // complicated.
    if (prefix_for_basetype(config.typename, &config.size)) {
        if (!allocvar || interactive_shell) {
            printf("%lu\n", config.size);
        }

        if (allocvar) {
            // NOTE: This is not a leak.
            snprintf(allocval, sizeof allocval, "pointer:%p", calloc(1, config.size));
            bind_variable(allocvar, allocval, 0);
        }
        return EXECUTION_SUCCESS;
    }

    dwarves__init(0);

    // For each loaded library...
    dl_iterate_phdr(shared_library_callback, &config);

    if (config.result != EXECUTION_SUCCESS) {
        builtin_warning("%s could not be found; check `help struct` for more",
                        config.typename);
    } else {
        if (!allocvar || interactive_shell) {
            printf("%lu\n", config.size);
        }

        if (allocvar) {
            // NOTE: This is not a leak.
            snprintf(allocval, sizeof allocval, "pointer:%p", calloc(1, config.size));
            bind_variable(allocvar, allocval, 0);
        }
    }

    cus__delete(config.cus);
    dwarves__exit();
    return config.result;
}

static char *struct_usage[] = {
    "",
    "Automatically define a standard structure.",
    "",
    "The struct command searches for the specified structure definition and",
    "attempts to create a matching bash array for use with the pack and",
    "unpack commands. This simplifies the process of creating complicated",
    "structures.",
    "",
    "This command uses compiler debug information to reconstruct types. If",
    "the command fails, it's possible that the debugging information is",
    "missing. Try these steps:",
    "",
    "   * On Fedora, RedHat or CentOS, try debuginfo-install <library>",
    "   * On Debian or Ubuntu, try apt-get install <library>-dbg",
    "   * On FreeBSD, enable WITH_DEBUG_FILES in src.conf and recompile",
    "   * If this is your own library, don't use strip",
    "",
    "If none of these are possible, you may have to define the structure",
    "manually, see the online documentation for details.",
    "",
    "Unions",
    "",
    "Because unions do not map onto any bash data type, you must select the",
    "union member you would like ctypes to use. Consider a structure like",
    "this:",
    "   struct example {",
    "        union { int a; float b; } foo;",
    "        union { long c; double d } bar;",
    "   }",
    "",
    "By default, you will get the first member of each union. If that's not",
    "what you want, you need to do this:",
    "   $ struct -u foo:a,bar:c example myvar",
    "",
    "Note that anonymous unions are supported, just omit the unionname.",
    "",
    "Anonymous Structures",
    "",
    "It is common to see structure definitions like this:",
    "   typedef struct {",
    "       int foo;",
    "   } type_t;",
    "",
    "This is an anonymous struct that is referenced via typedef. As the",
    "structure has no name, use -a and specify the typedef name instead.",
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
    "Options:",
    "    -u unionstr    Specify which union members to select.",
    "    -a             Structure is the typedef of an anonymous struct.",
    "    -m varname     Allocate a buffer for this structure.",
    NULL,
};

static char *sizeof_usage[] = {
    "",
    "Calculate the size of a standard structure.",
    "",
    "Print the size of bytes of the specified structure. See the struct",
    "command for more information. Some primitive types are supported",
    "such as int and long.",
    "",
    "A sequence like this is common, to create a structure and a buffer",
    "to use with pack and unpack:",
    "",
    "   struct foo bar",
    "   dlcall -r pointer -n fooptr malloc $(sizeof foo)",
    "",
    "This can be simplified to this:",
    "",
    "   struct foo bar",
    "   sizeof -m fooptr bar",
    "",
    "Note that you will need to free the buffer when you're finished, using",
    "dlcall free $fooptr.",
    "",
    "Options:",
    "   -a          Structure is the typedef of an anonymous struct.",
    "   -m varname  Allocate a buffer for this structure or type name.",
    NULL,
};

struct builtin __attribute__((visibility("default"))) struct_struct = {
    .name       = "struct",
    .function   = generate_standard_struct,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = struct_usage,
    .short_doc  = "struct [-a] [-u unionstr] [-m ptrname] STRUCTNAME VARNAME",
    .handle     = NULL,
};

struct builtin __attribute__((visibility("default"))) sizeof_struct = {
    .name       = "sizeof",
    .function   = sizeof_standard_struct,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = sizeof_usage,
    .short_doc  = "sizeof [-a] [-m ptrname] STRUCTNAME",
    .handle     = NULL,
};
