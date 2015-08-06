#ifndef __TYPES_H
#define __TYPES_H

bool decode_primitive_type(const char *parameter, void **value, ffi_type **type);
bool decode_type_prefix(const char *prefix, const char *value, ffi_type **type, void **result, char **pformat);
char * encode_primitive_type(const char *format, ffi_type *type, void *value);

#endif
