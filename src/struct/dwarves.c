/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007 Red Hat Inc.
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <assert.h>
#include <dirent.h>
#include <dwarf.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libelf.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "config.h"
#include "list.h"
#include "dwarves.h"
#include "dutil.h"
#include "strings.h"
#include <obstack.h>

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

const char *cu__string(const struct cu *cu, strings_t s)
{
	if (cu->dfops && cu->dfops->strings__ptr)
		return cu->dfops->strings__ptr(cu, s);
	return NULL;
}

static inline const char *s(const struct cu *cu, strings_t i)
{
	return cu__string(cu, i);
}

int __tag__has_type_loop(const struct tag *tag, const struct tag *type,
			 char *bf, size_t len, FILE *fp,
			 const char *fn, int line)
{
	char bbf[2048], *abf = bbf;

	if (type == NULL)
		return 0;

	if (tag->type == type->type) {
		int printed;

		if (bf != NULL)
			abf = bf;
		else
			len = sizeof(bbf);
		printed = snprintf(abf, len, "<ERROR(%s:%d): detected type loop: type=%d, tag=%s>",
			 fn, line, tag->type, dwarf_tag_name(tag->tag));
		if (bf == NULL)
			printed = fprintf(fp ?: stderr, "%s\n", abf);
		return printed;
	}

	return 0;
}

static void lexblock__delete_tags(struct tag *tag, struct cu *cu)
{
	struct lexblock *block = tag__lexblock(tag);
	struct tag *pos, *n;

	list_for_each_entry_safe_reverse(pos, n, &block->tags, node) {
		list_del_init(&pos->node);
		tag__delete(pos, cu);
	}
}

void lexblock__delete(struct lexblock *block, struct cu *cu)
{
	lexblock__delete_tags(&block->ip.tag, cu);
	obstack_free(&cu->obstack, block);
}

void tag__delete(struct tag *tag, struct cu *cu)
{
	assert(list_empty(&tag->node));

	switch (tag->tag) {
	case DW_TAG_union_type:
		type__delete(tag__type(tag), cu);		break;
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		class__delete(tag__class(tag), cu);		break;
	case DW_TAG_enumeration_type:
		enumeration__delete(tag__type(tag), cu);	break;
	case DW_TAG_subroutine_type:
		ftype__delete(tag__ftype(tag), cu);		break;
	case DW_TAG_subprogram:
		function__delete(tag__function(tag), cu);	break;
	case DW_TAG_lexical_block:
		lexblock__delete(tag__lexblock(tag), cu);	break;
	default:
		obstack_free(&cu->obstack, tag);
	}
}

void tag__not_found_die(const char *file, int line, const char *func)
{
	fprintf(stderr, "%s::%s(%d): tag not found, please report to "
			"acme@ghostprotocols.net\n", file, func, line);
	exit(1);
}

struct tag *tag__follow_typedef(const struct tag *tag, const struct cu *cu)
{
	struct tag *type = cu__type(cu, tag->type);

	if (type != NULL && tag__is_typedef(type))
		return tag__follow_typedef(type, cu);

	return type;
}

size_t __tag__id_not_found_fprintf(FILE *fp, uint16_t id,
				   const char *fn, int line)
{
	return fprintf(fp, "<ERROR(%s:%d): %d not found!>\n", fn, line, id);
}

static struct base_type_name_to_size {
	const char *name;
	strings_t  sname;
	size_t	   size;
} base_type_name_to_size_table[] = {
	{ .name = "unsigned",		    .size = 32, },
	{ .name = "signed int",		    .size = 32, },
	{ .name = "unsigned int",  	    .size = 32, },
	{ .name = "int",		    .size = 32, },
	{ .name = "short unsigned int",	    .size = 16, },
	{ .name = "signed short",	    .size = 16, },
	{ .name = "unsigned short",	    .size = 16, },
	{ .name = "short int",		    .size = 16, },
	{ .name = "char",		    .size =  8, },
	{ .name = "signed char",	    .size =  8, },
	{ .name = "unsigned char",	    .size =  8, },
	{ .name = "signed long",	    .size =  0, },
	{ .name = "long int",		    .size =  0, },
	{ .name = "signed long",	    .size =  0, },
	{ .name = "unsigned long",	    .size =  0, },
	{ .name = "long unsigned int",	    .size =  0, },
	{ .name = "bool",		    .size =  8, },
	{ .name = "_Bool",		    .size =  8, },
	{ .name = "long long unsigned int", .size = 64, },
	{ .name = "long long int",	    .size = 64, },
	{ .name = "signed long long",	    .size = 64, },
	{ .name = "unsigned long long",	    .size = 64, },
	{ .name = "double",		    .size = 64, },
	{ .name = "double double",	    .size = 64, },
	{ .name = "single float",	    .size = 32, },
	{ .name = "float",		    .size = 32, },
	{ .name = "long double",	    .size = 64, },
	{ .name = "long double long double", .size = 64, },
	{ .name = NULL },
};

void base_type_name_to_size_table__init(struct strings *strings)
{
	int i = 0;

	while (base_type_name_to_size_table[i].name != NULL) {
		if (base_type_name_to_size_table[i].sname == 0)
			base_type_name_to_size_table[i].sname =
			  strings__find(strings,
					base_type_name_to_size_table[i].name);
		++i;
	}
}

size_t base_type__name_to_size(struct base_type *bt, struct cu *cu)
{
	int i = 0;
	char bf[64];
	const char *name;

	if (bt->name_has_encoding)
		name = s(cu, bt->name);
	else
		name = base_type__name(bt, cu, bf, sizeof(bf));

	while (base_type_name_to_size_table[i].name != NULL) {
		if (bt->name_has_encoding) {
			if (base_type_name_to_size_table[i].sname == bt->name) {
				size_t size;
found:
				size = base_type_name_to_size_table[i].size;

				return size ?: ((size_t)cu->addr_size * 8);
			}
		} else if (strcmp(base_type_name_to_size_table[i].name,
				  name) == 0)
			goto found;
		++i;
	}
	fprintf(stderr, "%s: %s %s\n",
		 __func__, dwarf_tag_name(bt->tag.tag), name);
	return 0;
}

static const char *base_type_fp_type_str[] = {
	[BT_FP_SINGLE]	   = "single",
	[BT_FP_DOUBLE]	   = "double",
	[BT_FP_CMPLX]	   = "complex",
	[BT_FP_CMPLX_DBL]  = "complex double",
	[BT_FP_CMPLX_LDBL] = "complex long double",
	[BT_FP_LDBL]	   = "long double",
	[BT_FP_INTVL]	   = "interval",
	[BT_FP_INTVL_DBL]  = "interval double",
	[BT_FP_INTVL_LDBL] = "interval long double",
	[BT_FP_IMGRY]	   = "imaginary",
	[BT_FP_IMGRY_DBL]  = "imaginary double",
	[BT_FP_IMGRY_LDBL] = "imaginary long double",
};

const char *base_type__name(const struct base_type *bt, const struct cu *cu,
			    char *bf, size_t len)
{
	if (bt->name_has_encoding)
		return s(cu, bt->name);

	if (bt->float_type)
		snprintf(bf, len, "%s %s",
			 base_type_fp_type_str[bt->float_type],
			 s(cu, bt->name));
	else
		snprintf(bf, len, "%s%s%s%s",
			 bt->is_signed ? "signed " : "",
			 bt->is_bool ? "bool " : "",
			 bt->is_varargs ? "... " : "",
			 s(cu, bt->name));
	return bf;
}

void namespace__delete(struct namespace *space, struct cu *cu)
{
	struct tag *pos, *n;

	namespace__for_each_tag_safe_reverse(space, pos, n) {
		list_del_init(&pos->node);

		/* Look for nested namespaces */
		if (tag__has_namespace(pos))
			namespace__delete(tag__namespace(pos), cu);
		tag__delete(pos, cu);
	}

	tag__delete(&space->tag, cu);
}

struct class_member *
	type__find_first_biggest_size_base_type_member(struct type *type,
						       const struct cu *cu)
{
	struct class_member *pos, *result = NULL;
	size_t result_size = 0;

	type__for_each_data_member(type, pos) {
		if (pos->is_static)
			continue;

		struct tag *type = cu__type(cu, pos->tag.type);
		size_t member_size = 0, power2;
		struct class_member *inner = NULL;

		if (type == NULL) {
			tag__id_not_found_fprintf(stderr, pos->tag.type);
			continue;
		}
reevaluate:
		switch (type->tag) {
		case DW_TAG_base_type:
			member_size = base_type__size(type);
			break;
		case DW_TAG_pointer_type:
		case DW_TAG_reference_type:
			member_size = cu->addr_size;
			break;
		case DW_TAG_class_type:
		case DW_TAG_union_type:
		case DW_TAG_structure_type:
			if (tag__type(type)->nr_members == 0)
				continue;
			inner = type__find_first_biggest_size_base_type_member(tag__type(type), cu);
			member_size = inner->byte_size;
			break;
		case DW_TAG_array_type:
		case DW_TAG_const_type:
		case DW_TAG_typedef:
		case DW_TAG_rvalue_reference_type:
		case DW_TAG_volatile_type: {
			struct tag *tag = cu__type(cu, type->type);
			if (type == NULL) {
				tag__id_not_found_fprintf(stderr, type->type);
				continue;
			}
			type = tag;
		}
			goto reevaluate;
		case DW_TAG_enumeration_type:
			member_size = tag__type(type)->size / 8;
			break;
		}

		/* long long */
		if (member_size > cu->addr_size)
			return pos;

		for (power2 = cu->addr_size; power2 > result_size; power2 /= 2)
			if (member_size >= power2) {
				if (power2 == cu->addr_size)
					return inner ?: pos;
				result_size = power2;
				result = inner ?: pos;
			}
	}

	return result;
}

static void cu__find_class_holes(struct cu *cu)
{
	uint16_t id;
	struct class *pos;

	cu__for_each_struct(cu, id, pos)
		class__find_holes(pos);
}

void cus__add(struct cus *cus, struct cu *cu)
{
	list_add_tail(&cu->node, &cus->cus);
	cu__find_class_holes(cu);
}

static void ptr_table__init(struct ptr_table *pt)
{
	pt->entries = NULL;
	pt->nr_entries = pt->allocated_entries = 0;
}

static void ptr_table__exit(struct ptr_table *pt)
{
	free(pt->entries);
	pt->entries = NULL;
}

static long ptr_table__add(struct ptr_table *pt, void *ptr)
{
	const uint32_t nr_entries = pt->nr_entries + 1;
	const long rc = pt->nr_entries;

	if (nr_entries > pt->allocated_entries) {
		uint32_t allocated_entries = pt->allocated_entries + 256;
		void *entries = realloc(pt->entries,
					sizeof(void *) * allocated_entries);
		if (entries == NULL)
			return -ENOMEM;

		pt->allocated_entries = allocated_entries;
		pt->entries = entries;
	}

	pt->entries[rc] = ptr;
	pt->nr_entries = nr_entries;
	return rc;
}

static int ptr_table__add_with_id(struct ptr_table *pt, void *ptr,
				  uint32_t id)
{
	/* Assume we won't be fed with the same id more than once */
	if (id >= pt->allocated_entries) {
		uint32_t allocated_entries = roundup(id + 1, 256);
		void *entries = realloc(pt->entries,
					sizeof(void *) * allocated_entries);
		if (entries == NULL)
			return -ENOMEM;

		pt->allocated_entries = allocated_entries;
		pt->entries = entries;
	}

	pt->entries[id] = ptr;
	++pt->nr_entries;
	return 0;
}

static void *ptr_table__entry(const struct ptr_table *pt, uint32_t id)
{
	return id >= pt->nr_entries ? NULL : pt->entries[id];
}

static void cu__insert_function(struct cu *cu, struct tag *tag)
{
	struct function *function = tag__function(tag);
        struct rb_node **p = &cu->functions.rb_node;
        struct rb_node *parent = NULL;
        struct function *f;

        while (*p != NULL) {
                parent = *p;
                f = rb_entry(parent, struct function, rb_node);
                if (function->lexblock.ip.addr < f->lexblock.ip.addr)
                        p = &(*p)->rb_left;
                else
                        p = &(*p)->rb_right;
        }
        rb_link_node(&function->rb_node, parent, p);
        rb_insert_color(&function->rb_node, &cu->functions);
}

int cu__table_add_tag(struct cu *cu, struct tag *tag, long *id)
{
	struct ptr_table *pt = &cu->tags_table;

	if (tag__is_tag_type(tag))
		pt = &cu->types_table;
	else if (tag__is_function(tag)) {
		pt = &cu->functions_table;
		cu__insert_function(cu, tag);
	}

	if (*id < 0) {
		*id = ptr_table__add(pt, tag);
		if (*id < 0)
			return -ENOMEM;
	} else if (ptr_table__add_with_id(pt, tag, *id) < 0)
		return -ENOMEM;
	return 0;
}

int cu__table_nullify_type_entry(struct cu *cu, uint32_t id)
{
	return ptr_table__add_with_id(&cu->types_table, NULL, id);
}

int cu__add_tag(struct cu *cu, struct tag *tag, long *id)
{
	int err = cu__table_add_tag(cu, tag, id);

	if (err == 0)
		list_add_tail(&tag->node, &cu->tags);

	return err;
}

struct cu *cu__new(const char *name, uint8_t addr_size,
		   const unsigned char *build_id, int build_id_len,
		   const char *filename)
{
	struct cu *cu = malloc(sizeof(*cu) + build_id_len);

	if (cu != NULL) {
		cu->name = strdup(name);
		cu->filename = strdup(filename);
		if (cu->name == NULL || cu->filename == NULL)
			goto out_free;

		obstack_init(&cu->obstack);
		ptr_table__init(&cu->tags_table);
		ptr_table__init(&cu->types_table);
		ptr_table__init(&cu->functions_table);
		/*
		 * the first entry is historically associated with void,
		 * so make sure we don't use it
		 */
		if (ptr_table__add(&cu->types_table, NULL) < 0)
			goto out_free_name;

		cu->functions = RB_ROOT;

		cu->dfops	= NULL;
		INIT_LIST_HEAD(&cu->tags);
		INIT_LIST_HEAD(&cu->tool_list);

		cu->addr_size = addr_size;
		cu->extra_dbg_info = 0;

		cu->nr_inline_expansions   = 0;
		cu->size_inline_expansions = 0;
		cu->nr_structures_changed  = 0;
		cu->nr_functions_changed   = 0;
		cu->max_len_changed_item   = 0;
		cu->function_bytes_added   = 0;
		cu->function_bytes_removed = 0;
		cu->build_id_len	   = build_id_len;
		if (build_id_len > 0)
			memcpy(cu->build_id, build_id, build_id_len);
	}
out:
	return cu;
out_free_name:
	free(cu->name);
	free(cu->filename);
out_free:
	free(cu);
	cu = NULL;
	goto out;
}

void cu__delete(struct cu *cu)
{
	ptr_table__exit(&cu->tags_table);
	ptr_table__exit(&cu->types_table);
	ptr_table__exit(&cu->functions_table);
	if (cu->dfops && cu->dfops->cu__delete)
		cu->dfops->cu__delete(cu);
	obstack_free(&cu->obstack, NULL);
	free(cu->filename);
	free(cu->name);
	free(cu);
}

bool cu__same_build_id(const struct cu *cu, const struct cu *other)
{
	return cu->build_id_len != 0 &&
	       cu->build_id_len == other->build_id_len &&
	       memcmp(cu->build_id, other->build_id, cu->build_id_len) == 0;
}

struct tag *cu__function(const struct cu *cu, const uint32_t id)
{
	return cu ? ptr_table__entry(&cu->functions_table, id) : NULL;
}

struct tag *cu__tag(const struct cu *cu, const uint32_t id)
{
	return cu ? ptr_table__entry(&cu->tags_table, id) : NULL;
}

struct tag *cu__type(const struct cu *cu, const uint16_t id)
{
	return cu ? ptr_table__entry(&cu->types_table, id) : NULL;
}

struct tag *cu__find_first_typedef_of_type(const struct cu *cu,
					   const uint16_t type)
{
	uint16_t id;
	struct tag *pos;

	if (cu == NULL || type == 0)
		return NULL;

	cu__for_each_type(cu, id, pos)
		if (tag__is_typedef(pos) && pos->type == type)
			return pos;

	return NULL;
}

struct tag *cu__find_base_type_by_name(const struct cu *cu,
				       const char *name, uint16_t *idp)
{
	uint16_t id;
	struct tag *pos;

	if (cu == NULL || name == NULL)
		return NULL;

	cu__for_each_type(cu, id, pos) {
		if (pos->tag != DW_TAG_base_type)
			continue;

		const struct base_type *bt = tag__base_type(pos);
		char bf[64];
		const char *bname = base_type__name(bt, cu, bf, sizeof(bf));
		if (!bname || strcmp(bname, name) != 0)
			continue;

		if (idp != NULL)
			*idp = id;
		return pos;
	}

	return NULL;
}

struct tag *cu__find_base_type_by_sname_and_size(const struct cu *cu,
						 strings_t sname,
						 uint16_t bit_size,
						 uint16_t *idp)
{
	uint16_t id;
	struct tag *pos;

	if (sname == 0)
		return NULL;

	cu__for_each_type(cu, id, pos) {
		if (pos->tag == DW_TAG_base_type) {
			const struct base_type *bt = tag__base_type(pos);

			if (bt->bit_size == bit_size &&
			    bt->name == sname) {
				if (idp != NULL)
					*idp = id;
				return pos;
			}
		}
	}

	return NULL;
}

struct tag *cu__find_enumeration_by_sname_and_size(const struct cu *cu,
						   strings_t sname,
						   uint16_t bit_size,
						   uint16_t *idp)
{
	uint16_t id;
	struct tag *pos;

	if (sname == 0)
		return NULL;

	cu__for_each_type(cu, id, pos) {
		if (pos->tag == DW_TAG_enumeration_type) {
			const struct type *t = tag__type(pos);

			if (t->size == bit_size &&
			    t->namespace.name == sname) {
				if (idp != NULL)
					*idp = id;
				return pos;
			}
		}
	}

	return NULL;
}

struct tag *cu__find_struct_by_sname(const struct cu *cu, strings_t sname,
				     const int include_decls, uint16_t *idp)
{
	uint16_t id;
	struct tag *pos;

	if (sname == 0)
		return NULL;

	cu__for_each_type(cu, id, pos) {
		struct type *type;

		if (!tag__is_struct(pos))
			continue;

		type = tag__type(pos);
		if (type->namespace.name == sname) {
			if (!type->declaration)
				goto found;

			if (include_decls)
				goto found;
		}
	}

	return NULL;
found:
	if (idp != NULL)
		*idp = id;
	return pos;

}

struct tag *cu__find_struct_by_name(const struct cu *cu, const char *name,
				    const int include_decls, uint16_t *idp)
{
	if (cu == NULL || name == NULL)
		return NULL;

	uint16_t id;
	struct tag *pos;
	cu__for_each_type(cu, id, pos) {
		struct type *type;

		if (!tag__is_struct(pos))
			continue;

		type = tag__type(pos);
		const char *tname = type__name(type, cu);
		if (tname && strcmp(tname, name) == 0) {
			if (!type->declaration)
				goto found;

			if (include_decls)
				goto found;
		}
	}

	return NULL;
found:
	if (idp != NULL)
		*idp = id;
	return pos;
}

struct tag *cus__find_struct_by_name(const struct cus *cus,
				     struct cu **cu, const char *name,
				     const int include_decls, uint16_t *id)
{
	struct cu *pos;

	list_for_each_entry(pos, &cus->cus, node) {
		struct tag *tag = cu__find_struct_by_name(pos, name,
							  include_decls,
							  id);
		if (tag != NULL) {
			if (cu != NULL)
				*cu = pos;
			return tag;
		}
	}

	return NULL;
}

struct function *cu__find_function_at_addr(const struct cu *cu,
					   uint64_t addr)
{
        struct rb_node *n;

        if (cu == NULL)
                return NULL;

        n = cu->functions.rb_node;

        while (n) {
                struct function *f = rb_entry(n, struct function, rb_node);

                if (addr < f->lexblock.ip.addr)
                        n = n->rb_left;
                else if (addr >= f->lexblock.ip.addr + f->lexblock.size)
                        n = n->rb_right;
                else
                        return f;
        }

        return NULL;

}

struct function *cus__find_function_at_addr(const struct cus *cus,
					    uint64_t addr, struct cu **cu)
{
	struct cu *pos;

	list_for_each_entry(pos, &cus->cus, node) {
		struct function *f = cu__find_function_at_addr(pos, addr);

		if (f != NULL) {
			if (cu != NULL)
				*cu = pos;
			return f;
		}
	}
	return NULL;
}

struct cu *cus__find_cu_by_name(const struct cus *cus, const char *name)
{
	struct cu *pos;

	list_for_each_entry(pos, &cus->cus, node)
		if (pos->name && strcmp(pos->name, name) == 0)
			return pos;

	return NULL;
}

struct tag *cu__find_function_by_name(const struct cu *cu, const char *name)
{
	if (cu == NULL || name == NULL)
		return NULL;

	uint32_t id;
	struct function *pos;
	cu__for_each_function(cu, id, pos) {
		const char *fname = function__name(pos, cu);
		if (fname && strcmp(fname, name) == 0)
			return function__tag(pos);
	}

	return NULL;
}

static size_t array_type__nr_entries(const struct array_type *at)
{
	int i;
	size_t nr_entries = 1;

	for (i = 0; i < at->dimensions; ++i)
		nr_entries *= at->nr_entries[i];

	return nr_entries;
}

size_t tag__size(const struct tag *tag, const struct cu *cu)
{
	size_t size;

	switch (tag->tag) {
	case DW_TAG_member: {
		struct class_member *member = tag__class_member(tag);
		if (member->is_static)
			return 0;
		/* Is it cached already? */
		size = member->byte_size;
		if (size != 0)
			return size;
		break;
	}
	case DW_TAG_pointer_type:
	case DW_TAG_reference_type:	return cu->addr_size;
	case DW_TAG_base_type:		return base_type__size(tag);
	case DW_TAG_enumeration_type:	return tag__type(tag)->size / 8;
	}

	if (tag->type == 0) { /* struct class: unions, structs */
		struct type *type = tag__type(tag);

		/* empty base optimization trick */
		if (type->size == 1 && type->nr_members == 0)
			size = 0;
		else
			size = tag__type(tag)->size;
	} else {
		const struct tag *type = cu__type(cu, tag->type);

		if (type == NULL) {
			tag__id_not_found_fprintf(stderr, tag->type);
			return -1;
		} else if (tag__has_type_loop(tag, type, NULL, 0, NULL))
			return -1;
		size = tag__size(type, cu);
	}

	if (tag->tag == DW_TAG_array_type)
		return size * array_type__nr_entries(tag__array_type(tag));

	return size;
}

const char *variable__name(const struct dwvariable *var, const struct cu *cu)
{
	if (cu->dfops && cu->dfops->variable__name)
		return cu->dfops->variable__name(var, cu);
	return s(cu, var->name);
}

const char *variable__type_name(const struct dwvariable *var,
				const struct cu *cu,
				char *bf, size_t len)
{
	const struct tag *tag = cu__type(cu, var->ip.tag.type);
	return tag != NULL ? tag__name(tag, cu, bf, len, NULL) : NULL;
}

void class_member__delete(struct class_member *member, struct cu *cu)
{
	obstack_free(&cu->obstack, member);
}

static struct class_member *class_member__clone(const struct class_member *from,
						struct cu *cu)
{
	struct class_member *member = obstack_alloc(&cu->obstack, sizeof(*member));

	if (member != NULL)
		memcpy(member, from, sizeof(*member));

	return member;
}

static void type__delete_class_members(struct type *type, struct cu *cu)
{
	struct class_member *pos, *next;

	type__for_each_tag_safe_reverse(type, pos, next) {
		list_del_init(&pos->tag.node);
		class_member__delete(pos, cu);
	}
}

void class__delete(struct class *class, struct cu *cu)
{
	if (class->type.namespace.sname != NULL)
		free(class->type.namespace.sname);
	type__delete_class_members(&class->type, cu);
	obstack_free(&cu->obstack, class);
}

void type__delete(struct type *type, struct cu *cu)
{
	type__delete_class_members(type, cu);
	obstack_free(&cu->obstack, type);
}

static void enumerator__delete(struct enumerator *enumerator, struct cu *cu)
{
	obstack_free(&cu->obstack, enumerator);
}

void enumeration__delete(struct type *type, struct cu *cu)
{
	struct enumerator *pos, *n;
	type__for_each_enumerator_safe_reverse(type, pos, n) {
		list_del_init(&pos->tag.node);
		enumerator__delete(pos, cu);
	}
}

void class__add_vtable_entry(struct class *class, struct function *vtable_entry)
{
	++class->nr_vtable_entries;
	list_add_tail(&vtable_entry->vtable_node, &class->vtable);
}

void namespace__add_tag(struct namespace *space, struct tag *tag)
{
	++space->nr_tags;
	list_add_tail(&tag->node, &space->tags);
}

void type__add_member(struct type *type, struct class_member *member)
{
	if (member->is_static)
		++type->nr_static_members;
	else
		++type->nr_members;
	namespace__add_tag(&type->namespace, &member->tag);
}

struct class_member *type__last_member(struct type *type)
{
	struct class_member *pos;

	list_for_each_entry_reverse(pos, &type->namespace.tags, tag.node)
		if (pos->tag.tag == DW_TAG_member)
			return pos;
	return NULL;
}

static int type__clone_members(struct type *type, const struct type *from,
			       struct cu *cu)
{
	struct class_member *pos;

	type->nr_members = type->nr_static_members = 0;
	INIT_LIST_HEAD(&type->namespace.tags);

	type__for_each_member(from, pos) {
		struct class_member *clone = class_member__clone(pos, cu);

		if (clone == NULL)
			return -1;
		type__add_member(type, clone);
	}

	return 0;
}

struct class *class__clone(const struct class *from,
			   const char *new_class_name, struct cu *cu)
{
	struct class *class = obstack_alloc(&cu->obstack, sizeof(*class));

	 if (class != NULL) {
		memcpy(class, from, sizeof(*class));
		if (new_class_name != NULL) {
			class->type.namespace.name = 0;
			class->type.namespace.sname = strdup(new_class_name);
			if (class->type.namespace.sname == NULL) {
				free(class);
				return NULL;
			}
		}
		if (type__clone_members(&class->type, &from->type, cu) != 0) {
			class__delete(class, cu);
			class = NULL;
		}
	}

	return class;
}

void enumeration__add(struct type *type, struct enumerator *enumerator)
{
	++type->nr_members;
	namespace__add_tag(&type->namespace, &enumerator->tag);
}

void lexblock__add_lexblock(struct lexblock *block, struct lexblock *child)
{
	++block->nr_lexblocks;
	list_add_tail(&child->ip.tag.node, &block->tags);
}

const char *function__name(struct function *func, const struct cu *cu)
{
	if (cu->dfops && cu->dfops->function__name)
		return cu->dfops->function__name(func, cu);
	return s(cu, func->name);
}

static void parameter__delete(struct parameter *parm, struct cu *cu)
{
	obstack_free(&cu->obstack, parm);
}

void ftype__delete(struct ftype *type, struct cu *cu)
{
	struct parameter *pos, *n;

	if (type == NULL)
		return;

	ftype__for_each_parameter_safe_reverse(type, pos, n) {
		list_del_init(&pos->tag.node);
		parameter__delete(pos, cu);
	}
	obstack_free(&cu->obstack, type);
}

void function__delete(struct function *func, struct cu *cu)
{
	lexblock__delete_tags(&func->lexblock.ip.tag, cu);
	ftype__delete(&func->proto, cu);
}

int ftype__has_parm_of_type(const struct ftype *ftype, const uint16_t target,
			    const struct cu *cu)
{
	struct parameter *pos;

	ftype__for_each_parameter(ftype, pos) {
		struct tag *type = cu__type(cu, pos->tag.type);

		if (type != NULL && type->tag == DW_TAG_pointer_type) {
			if (type->type == target)
				return 1;
		}
	}
	return 0;
}

void ftype__add_parameter(struct ftype *ftype, struct parameter *parm)
{
	++ftype->nr_parms;
	list_add_tail(&parm->tag.node, &ftype->parms);
}

void lexblock__add_tag(struct lexblock *block, struct tag *tag)
{
	list_add_tail(&tag->node, &block->tags);
}

void lexblock__add_inline_expansion(struct lexblock *block,
				    struct inline_expansion *exp)
{
	++block->nr_inline_expansions;
	block->size_inline_expansions += exp->size;
	lexblock__add_tag(block, &exp->ip.tag);
}

void lexblock__add_variable(struct lexblock *block, struct dwvariable *var)
{
	++block->nr_variables;
	lexblock__add_tag(block, &var->ip.tag);
}

void lexblock__add_label(struct lexblock *block, struct label *label)
{
	++block->nr_labels;
	lexblock__add_tag(block, &label->ip.tag);
}

const struct class_member *class__find_bit_hole(const struct class *class,
					    const struct class_member *trailer,
						const uint16_t bit_hole_size)
{
	struct class_member *pos;
	const size_t byte_hole_size = bit_hole_size / 8;

	type__for_each_data_member(&class->type, pos)
		if (pos == trailer)
			break;
		else if (pos->hole >= byte_hole_size ||
			 pos->bit_hole >= bit_hole_size)
			return pos;

	return NULL;
}

void class__find_holes(struct class *class)
{
	const struct type *ctype = &class->type;
	struct class_member *pos, *last = NULL;
	size_t last_size = 0;
	uint32_t bit_sum = 0;
	uint32_t bitfield_real_offset = 0;

	class->nr_holes = 0;
	class->nr_bit_holes = 0;

	type__for_each_member(ctype, pos) {
		/* XXX for now just skip these */
		if (pos->tag.tag == DW_TAG_inheritance &&
		    pos->virtuality == DW_VIRTUALITY_virtual)
			continue;

		if (pos->is_static)
			continue;

		if (last != NULL) {
			/*
			 * We have to cast both offsets to int64_t because
			 * the current offset can be before the last offset
			 * when we are starting a bitfield that combines with
			 * the previous, small size fields.
			 */
			const ssize_t cc_last_size = ((int64_t)pos->byte_offset -
						      (int64_t)last->byte_offset);

			/*
			 * If the offset is the same this better be a bitfield
			 * or an empty struct (see rwlock_t in the Linux kernel
			 * sources when compiled for UP) or...
			 */
			if (cc_last_size > 0) {
				/*
				 * Check if the DWARF byte_size info is smaller
				 * than the size used by the compiler, i.e.
				 * when combining small bitfields with the next
				 * member.
				*/
				if ((size_t)cc_last_size < last_size)
					last_size = cc_last_size;

				last->hole = cc_last_size - last_size;
				if (last->hole > 0)
					++class->nr_holes;

				if (bit_sum != 0) {
					if (bitfield_real_offset != 0) {
						last_size = bitfield_real_offset - last->byte_offset;
						bitfield_real_offset = 0;
					}

					last->bit_hole = (last_size * 8) -
							 bit_sum;
					if (last->bit_hole != 0)
						++class->nr_bit_holes;

					last->bitfield_end = 1;
					bit_sum = 0;
				}
			} else if (cc_last_size < 0 && bit_sum == 0)
				bitfield_real_offset = last->byte_offset + last_size;
		}

		bit_sum += pos->bitfield_size;

		/*
		 * check for bitfields, accounting for only the biggest of the
		 * byte_size in the fields in each bitfield set.
		 */

		if (last == NULL || last->byte_offset != pos->byte_offset ||
		    pos->bitfield_size == 0 || last->bitfield_size == 0) {
			last_size = pos->byte_size;
		} else if (pos->byte_size > last_size)
			last_size = pos->byte_size;

		last = pos;
	}

	if (last != NULL) {
		if (last->byte_offset + last_size != ctype->size)
			class->padding = ctype->size -
					(last->byte_offset + last_size);
		if (last->bitfield_size != 0)
			class->bit_padding = (last_size * 8) - bit_sum;
	} else
		/* No members? Zero sized C++ class */
		class->padding = 0;
}

/** class__has_hole_ge - check if class has a hole greater or equal to @size
 * @class - class instance
 * @size - hole size to check
 */
int class__has_hole_ge(const struct class *class, const uint16_t size)
{
	struct class_member *pos;

	if (class->nr_holes == 0)
		return 0;

	type__for_each_data_member(&class->type, pos)
		if (pos->hole >= size)
			return 1;

	return 0;
}

struct class_member *type__find_member_by_name(const struct type *type,
					       const struct cu *cu,
					       const char *name)
{
	if (name == NULL)
		return NULL;

	struct class_member *pos;
	type__for_each_data_member(type, pos) {
		const char *curr_name = class_member__name(pos, cu);
		if (curr_name && strcmp(curr_name, name) == 0)
			return pos;
	}

	return NULL;
}

uint32_t type__nr_members_of_type(const struct type *type, const uint16_t type_id)
{
	struct class_member *pos;
	uint32_t nr_members_of_type = 0;

	type__for_each_member(type, pos)
		if (pos->tag.type == type_id)
			++nr_members_of_type;

	return nr_members_of_type;
}

static void lexblock__account_inline_expansions(struct lexblock *block,
						const struct cu *cu)
{
	struct tag *pos, *type;

	if (block->nr_inline_expansions == 0)
		return;

	list_for_each_entry(pos, &block->tags, node) {
		if (pos->tag == DW_TAG_lexical_block) {
			lexblock__account_inline_expansions(tag__lexblock(pos),
							    cu);
			continue;
		} else if (pos->tag != DW_TAG_inlined_subroutine)
			continue;

		type = cu__function(cu, pos->type);
		if (type != NULL) {
			struct function *ftype = tag__function(type);

			ftype->cu_total_nr_inline_expansions++;
			ftype->cu_total_size_inline_expansions +=
					tag__inline_expansion(pos)->size;
		}

	}
}

void cu__account_inline_expansions(struct cu *cu)
{
	struct tag *pos;
	struct function *fpos;

	list_for_each_entry(pos, &cu->tags, node) {
		if (!tag__is_function(pos))
			continue;
		fpos = tag__function(pos);
		lexblock__account_inline_expansions(&fpos->lexblock, cu);
		cu->nr_inline_expansions   += fpos->lexblock.nr_inline_expansions;
		cu->size_inline_expansions += fpos->lexblock.size_inline_expansions;
	}
}

static int list__for_all_tags(struct list_head *list, struct cu *cu,
			      int (*iterator)(struct tag *tag,
					      struct cu *cu, void *cookie),
			      void *cookie)
{
	struct tag *pos, *n;

	list_for_each_entry_safe_reverse(pos, n, list, node) {
		if (tag__has_namespace(pos)) {
			struct namespace *space = tag__namespace(pos);

			/*
			 * See comment in type__for_each_enumerator, the
			 * enumerators (enum entries) are shared, but the
			 * enumeration tag must be deleted.
			 */
			if (!space->shared_tags &&
			    list__for_all_tags(&space->tags, cu,
					       iterator, cookie))
				return 1;
			/*
			 * vtable functions are already in the class tags list
			 */
		} else if (tag__is_function(pos)) {
			if (list__for_all_tags(&tag__ftype(pos)->parms,
					       cu, iterator, cookie))
				return 1;
			if (list__for_all_tags(&tag__function(pos)->lexblock.tags,
					       cu, iterator, cookie))
				return 1;
		} else if (pos->tag == DW_TAG_subroutine_type) {
			if (list__for_all_tags(&tag__ftype(pos)->parms,
					       cu, iterator, cookie))
				return 1;
		} else if (pos->tag == DW_TAG_lexical_block) {
			if (list__for_all_tags(&tag__lexblock(pos)->tags,
					       cu, iterator, cookie))
				return 1;
		}

		if (iterator(pos, cu, cookie))
			return 1;
	}
	return 0;
}

int cu__for_all_tags(struct cu *cu,
		     int (*iterator)(struct tag *tag,
				     struct cu *cu, void *cookie),
		     void *cookie)
{
	return list__for_all_tags(&cu->tags, cu, iterator, cookie);
}

void cus__for_each_cu(struct cus *cus,
		      int (*iterator)(struct cu *cu, void *cookie),
		      void *cookie,
		      struct cu *(*filter)(struct cu *cu))
{
	struct cu *pos;

	list_for_each_entry(pos, &cus->cus, node) {
		struct cu *cu = pos;
		if (filter != NULL) {
			cu = filter(pos);
			if (cu == NULL)
				continue;
		}
		if (iterator(cu, cookie))
			break;
	}
}

int cus__load_dir(struct cus *cus, struct conf_load *conf,
		  const char *dirname, const char *filename_mask,
		  const int recursive)
{
	struct dirent *entry;
	int err = -1;
	DIR *dir = opendir(dirname);

	if (dir == NULL)
		goto out;

	err = 0;
	while ((entry = readdir(dir)) != NULL) {
		char pathname[PATH_MAX];
		struct stat st;

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
		    continue;

		snprintf(pathname, sizeof(pathname), "%s/%s",
			 dirname, entry->d_name);

		err = lstat(pathname, &st);
		if (err != 0)
			break;

		if (S_ISDIR(st.st_mode)) {
			if (!recursive)
				continue;

			err = cus__load_dir(cus, conf, pathname,
					    filename_mask, recursive);
			if (err != 0)
				break;
		} else if (fnmatch(filename_mask, entry->d_name, 0) == 0) {
			err = cus__load_file(cus, conf, pathname);
			if (err != 0)
				break;
		}
	}

	if (err == -1)
		puts(dirname);
	closedir(dir);
out:
	return err;
}

/*
 * This should really do demand loading of DSOs, STABS anyone? 8-)
 */
extern struct debug_fmt_ops dwarf__ops, ctf__ops;

static struct debug_fmt_ops *debug_fmt_table[] = {
	&dwarf__ops,
	&ctf__ops,
	NULL,
};

static int debugging_formats__loader(const char *name)
{
	int i = 0;
	while (debug_fmt_table[i] != NULL) {
		if (strcmp(debug_fmt_table[i]->name, name) == 0)
			return i;
		++i;
	}
	return -1;
}

int cus__load_file(struct cus *cus, struct conf_load *conf,
		   const char *filename)
{
	int i = 0, err = 0;
	int loader;

	if (conf && conf->format_path != NULL) {
		char *fpath = strdup(conf->format_path);
		if (fpath == NULL)
			return -ENOMEM;
		char *fp = fpath;
		while (1) {
			char *sep = strchr(fp, ',');

			if (sep != NULL)
				*sep = '\0';

			err = -ENOTSUP;
			loader = debugging_formats__loader(fp);
			if (loader == -1)
				break;

			err = 0;
			if (debug_fmt_table[loader]->load_file(cus, conf,
							       filename) == 0)
				break;

			err = -EINVAL;
			if (sep == NULL)
				break;

			fp = sep + 1;
		}
		free(fpath);
		return err;
	}

	while (debug_fmt_table[i] != NULL) {
		if (debug_fmt_table[i]->load_file(cus, conf, filename) == 0)
			return 0;
		++i;
	}

	return -EINVAL;
}

int cus__load_files(struct cus *cus, struct conf_load *conf,
		    char *filenames[])
{
	int i = 0;

	while (filenames[i] != NULL) {
		if (cus__load_file(cus, conf, filenames[i]))
			return -++i;
		++i;
	}

	return 0;
}

int cus__fprintf_load_files_err(struct cus *cus, const char *tool, char *argv[], int err, FILE *output)
{
	/* errno is not properly preserved in some cases, sigh */
	return fprintf(output, "%s: %s: %s\n", tool, argv[-err - 1],
		       errno ? strerror(errno) : "No debugging information found");
}

struct cus *cus__new(void)
{
	struct cus *cus = malloc(sizeof(*cus));

	if (cus != NULL)
		INIT_LIST_HEAD(&cus->cus);

	return cus;
}

void cus__delete(struct cus *cus)
{
	struct cu *pos, *n;

	if (cus == NULL)
		return;

	list_for_each_entry_safe(pos, n, &cus->cus, node) {
		list_del_init(&pos->node);
		cu__delete(pos);
	}

	free(cus);
}

void dwarves__fprintf_init(uint16_t user_cacheline_size);

int dwarves__init(uint16_t user_cacheline_size)
{
	dwarves__fprintf_init(user_cacheline_size);

	int i = 0;
	int err = 0;

	while (debug_fmt_table[i] != NULL) {
		if (debug_fmt_table[i]->init) {
			err = debug_fmt_table[i]->init();
			if (err)
				goto out_fail;
		}
		++i;
	}

	return 0;
out_fail:
	while (i-- != 0)
		if (debug_fmt_table[i]->exit)
			debug_fmt_table[i]->exit();
	return err;
}

void dwarves__exit(void)
{
	int i = 0;

	while (debug_fmt_table[i] != NULL) {
		if (debug_fmt_table[i]->exit)
			debug_fmt_table[i]->exit();
		++i;
	}
}

struct argp_state;
