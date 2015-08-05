#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "util.h"

bool check_parse_long(const char *number, long *result)
{
    char *endptr;

    if (strlen(number) == 0)
        return false;

    *result = strtol(number, &endptr, 0);

    return *endptr == '\0';
}

bool check_parse_ulong(const char *number, unsigned long *result)
{
    char *endptr;

    if (strlen(number) == 0)
        return false;

    // Handle the special case of null pointers.
    if (strcmp(number, "(nil)") == 0 || strcmp(number, "(null)") == 0) {
        *result = 0;
        return true;
    }

    *result = strtoul(number, &endptr, 0);

    return *endptr == '\0';
}
