/* ctfdump.c: CTF dumper.
 *
 * Copyright (C) 2008 David S. Miller <davem@davemloft.net>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include <zlib.h>

#include <gelf.h>

#include "libctf.h"
#include "ctf.h"
#include "dutil.h"
#include "dwarves.h"

/*
 * FIXME: We should just get the table from the CTF ELF section
 * and use it directly
 */
extern struct strings *strings;

static void *tag__alloc(const size_t size)
{
	struct tag *tag = zalloc(size);

	if (tag != NULL)
		tag->top_level = 1;

	return tag;
}

static int ctf__load_ftype(struct ctf *ctf, struct ftype *proto, uint16_t tag,
			   uint16_t type, uint16_t vlen, uint16_t *args, long id)
{
	proto->tag.tag	= tag;
	proto->tag.type = type;
	INIT_LIST_HEAD(&proto->parms);

	int i;
	for (i = 0; i < vlen; i++) {
		uint16_t type = ctf__get16(ctf, &args[i]);

		if (type == 0)
			proto->unspec_parms = 1;
		else {
			struct parameter *p = tag__alloc(sizeof(*p));

			if (p == NULL)
				goto out_free_parameters;
			p->tag.tag  = DW_TAG_formal_parameter;
			p->tag.type = ctf__get16(ctf, &args[i]);
			ftype__add_parameter(proto, p);
		}
	}

	vlen *= sizeof(*args);

	/* Round up to next multiple of 4 to maintain
	 * 32-bit alignment.
	 */
	if (vlen & 0x2)
		vlen += 0x2;

	cu__add_tag(ctf->priv, &proto->tag, &id);

	return vlen;
out_free_parameters:
	ftype__delete(proto, ctf->priv);
	return -ENOMEM;
}

static struct function *function__new(uint16_t **ptr, GElf_Sym *sym,
				      struct ctf *ctf)
{
	struct function *func = tag__alloc(sizeof(*func));

	if (func != NULL) {
		func->lexblock.ip.addr = elf_sym__value(sym);
		func->lexblock.size = elf_sym__size(sym);
		func->name = sym->st_name;
		func->vtable_entry = -1;
		func->external = elf_sym__bind(sym) == STB_GLOBAL;
		INIT_LIST_HEAD(&func->vtable_node);
		INIT_LIST_HEAD(&func->tool_node);
		INIT_LIST_HEAD(&func->lexblock.tags);

		uint16_t val = ctf__get16(ctf, *ptr);
		uint16_t tag = CTF_GET_KIND(val);
		uint16_t vlen = CTF_GET_VLEN(val);

		++*ptr;

		if (tag != CTF_TYPE_KIND_FUNC) {
			fprintf(stderr,
				"%s: Expected function type, got %u\n",
				__func__, tag);
			goto out_delete;
		}
		uint16_t type = ctf__get16(ctf, *ptr);
		long id = -1; /* FIXME: not needed for funcs... */

		++*ptr;

		if (ctf__load_ftype(ctf, &func->proto, DW_TAG_subprogram,
				    type, vlen, *ptr, id) < 0)
			return NULL;
		/*
		 * Round up to next multiple of 4 to maintain 32-bit alignment.
		 */
		if (vlen & 0x1)
			++vlen;
		*ptr += vlen;
	}

	return func;
out_delete:
	free(func);
	return NULL;
}

static int ctf__load_funcs(struct ctf *ctf)
{
	struct ctf_header *hp = ctf__get_buffer(ctf);
	uint16_t *func_ptr = (ctf__get_buffer(ctf) + sizeof(*hp) +
			      ctf__get32(ctf, &hp->ctf_func_off));

	GElf_Sym sym;
	uint32_t idx;
	ctf__for_each_symtab_function(ctf, idx, sym)
		if (function__new(&func_ptr, &sym, ctf) == NULL)
			return -ENOMEM;

	return 0;
}

static struct base_type *base_type__new(strings_t name, uint32_t attrs,
					uint8_t float_type, size_t size)
{
        struct base_type *bt = tag__alloc(sizeof(*bt));

	if (bt != NULL) {
		bt->name = name;
		bt->bit_size = size;
		bt->is_signed = attrs & CTF_TYPE_INT_SIGNED;
		bt->is_bool = attrs & CTF_TYPE_INT_BOOL;
		bt->is_varargs = attrs & CTF_TYPE_INT_VARARGS;
		bt->name_has_encoding = false;
		bt->float_type = float_type;
	}
	return bt;
}

static void type__init(struct type *type, uint16_t tag,
		       strings_t name, size_t size)
{
	INIT_LIST_HEAD(&type->node);
	INIT_LIST_HEAD(&type->namespace.tags);
	type->size = size;
	type->namespace.tag.tag = tag;
	type->namespace.name = name;
	type->namespace.sname = 0;
}

static struct type *type__new(uint16_t tag, strings_t name, size_t size)
{
        struct type *type = tag__alloc(sizeof(*type));

	if (type != NULL)
		type__init(type, tag, name, size);

	return type;
}

static struct class *class__new(strings_t name, size_t size)
{
	struct class *class = tag__alloc(sizeof(*class));

	if (class != NULL) {
		type__init(&class->type, DW_TAG_structure_type, name, size);
		INIT_LIST_HEAD(&class->vtable);
	}

	return class;
}

static int create_new_base_type(struct ctf *ctf, void *ptr,
				struct ctf_full_type *tp, long id)
{
	uint32_t *enc = ptr;
	uint32_t eval = ctf__get32(ctf, enc);
	uint32_t attrs = CTF_TYPE_INT_ATTRS(eval);
	strings_t name = ctf__get32(ctf, &tp->base.ctf_name);
	struct base_type *base = base_type__new(name, attrs, 0,
						CTF_TYPE_INT_BITS(eval));
	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag(ctf->priv, &base->tag, &id);

	return sizeof(*enc);
}

static int create_new_base_type_float(struct ctf *ctf, void *ptr,
				      struct ctf_full_type *tp,
				      long id)
{
	strings_t name = ctf__get32(ctf, &tp->base.ctf_name);
	uint32_t *enc = ptr, eval = ctf__get32(ctf, enc);
	struct base_type *base = base_type__new(name, 0, eval,
						CTF_TYPE_FP_BITS(eval));
	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag(ctf->priv, &base->tag, &id);

	return sizeof(*enc);
}

static int create_new_array(struct ctf *ctf, void *ptr, long id)
{
	struct ctf_array *ap = ptr;
	struct array_type *array = tag__alloc(sizeof(*array));

	if (array == NULL)
		return -ENOMEM;

	/* FIXME: where to get the number of dimensions?
	 * it it flattened? */
	array->dimensions = 1;
	array->nr_entries = malloc(sizeof(uint32_t));

	if (array->nr_entries == NULL) {
		free(array);
		return -ENOMEM;
	}

	array->nr_entries[0] = ctf__get32(ctf, &ap->ctf_array_nelems);
	array->tag.tag = DW_TAG_array_type;
	array->tag.type = ctf__get16(ctf, &ap->ctf_array_type);

	cu__add_tag(ctf->priv, &array->tag, &id);

	return sizeof(*ap);
}

static int create_new_subroutine_type(struct ctf *ctf, void *ptr,
				      int vlen, struct ctf_full_type *tp,
				      long id)
{
	uint16_t *args = ptr;
	unsigned int type = ctf__get16(ctf, &tp->base.ctf_type);
	struct ftype *proto = tag__alloc(sizeof(*proto));

	if (proto == NULL)
		return -ENOMEM;

	vlen = ctf__load_ftype(ctf, proto, DW_TAG_subroutine_type,
			       type, vlen, args, id);
	return vlen < 0 ? -ENOMEM : vlen;
}

static int create_full_members(struct ctf *ctf, void *ptr,
			       int vlen, struct type *class)
{
	struct ctf_full_member *mp = ptr;
	int i;

	for (i = 0; i < vlen; i++) {
		struct class_member *member = zalloc(sizeof(*member));

		if (member == NULL)
			return -ENOMEM;

		member->tag.tag = DW_TAG_member;
		member->tag.type = ctf__get16(ctf, &mp[i].ctf_member_type);
		member->name = ctf__get32(ctf, &mp[i].ctf_member_name);
		member->bit_offset = (ctf__get32(ctf, &mp[i].ctf_member_offset_high) << 16) |
				      ctf__get32(ctf, &mp[i].ctf_member_offset_low);
		/* sizes and offsets will be corrected at class__fixup_ctf_bitfields */
		type__add_member(class, member);
	}

	return sizeof(*mp);
}

static int create_short_members(struct ctf *ctf, void *ptr,
				int vlen, struct type *class)
{
	struct ctf_short_member *mp = ptr;
	int i;

	for (i = 0; i < vlen; i++) {
		struct class_member *member = zalloc(sizeof(*member));

		if (member == NULL)
			return -ENOMEM;

		member->tag.tag = DW_TAG_member;
		member->tag.type = ctf__get16(ctf, &mp[i].ctf_member_type);
		member->name = ctf__get32(ctf, &mp[i].ctf_member_name);
		member->bit_offset = ctf__get16(ctf, &mp[i].ctf_member_offset);
		/* sizes and offsets will be corrected at class__fixup_ctf_bitfields */

		type__add_member(class, member);
	}

	return sizeof(*mp);
}

static int create_new_class(struct ctf *ctf, void *ptr,
			    int vlen, struct ctf_full_type *tp,
			    uint64_t size, long id)
{
	int member_size;
	strings_t name = ctf__get32(ctf, &tp->base.ctf_name);
	struct class *class = class__new(name, size);

	if (size >= CTF_SHORT_MEMBER_LIMIT) {
		member_size = create_full_members(ctf, ptr, vlen, &class->type);
	} else {
		member_size = create_short_members(ctf, ptr, vlen, &class->type);
	}

	if (member_size < 0)
		goto out_free;

	cu__add_tag(ctf->priv, &class->type.namespace.tag, &id);

	return (vlen * member_size);
out_free:
	class__delete(class, ctf->priv);
	return -ENOMEM;
}

static int create_new_union(struct ctf *ctf, void *ptr,
			    int vlen, struct ctf_full_type *tp,
			    uint64_t size, long id)
{
	int member_size;
	strings_t name = ctf__get32(ctf, &tp->base.ctf_name);
	struct type *un = type__new(DW_TAG_union_type, name, size);

	if (size >= CTF_SHORT_MEMBER_LIMIT) {
		member_size = create_full_members(ctf, ptr, vlen, un);
	} else {
		member_size = create_short_members(ctf, ptr, vlen, un);
	}

	if (member_size < 0)
		goto out_free;

	cu__add_tag(ctf->priv, &un->namespace.tag, &id);

	return (vlen * member_size);
out_free:
	type__delete(un, ctf->priv);
	return -ENOMEM;
}

static struct enumerator *enumerator__new(strings_t name, uint32_t value)
{
	struct enumerator *en = tag__alloc(sizeof(*en));

	if (en != NULL) {
		en->name = name;
		en->value = value;
		en->tag.tag = DW_TAG_enumerator;
	}

	return en;
}

static int create_new_enumeration(struct ctf *ctf, void *ptr,
				  int vlen, struct ctf_full_type *tp,
				  uint16_t size, long id)
{
	struct ctf_enum *ep = ptr;
	uint16_t i;
	struct type *enumeration = type__new(DW_TAG_enumeration_type,
					     ctf__get32(ctf,
							&tp->base.ctf_name),
					     size ?: (sizeof(int) * 8));

	if (enumeration == NULL)
		return -ENOMEM;

	for (i = 0; i < vlen; i++) {
		strings_t name = ctf__get32(ctf, &ep[i].ctf_enum_name);
		uint32_t value = ctf__get32(ctf, &ep[i].ctf_enum_val);
		struct enumerator *enumerator = enumerator__new(name, value);

		if (enumerator == NULL)
			goto out_free;

		enumeration__add(enumeration, enumerator);
	}

	cu__add_tag(ctf->priv, &enumeration->namespace.tag, &id);

	return (vlen * sizeof(*ep));
out_free:
	enumeration__delete(enumeration, ctf->priv);
	return -ENOMEM;
}

static int create_new_forward_decl(struct ctf *ctf, struct ctf_full_type *tp,
				   uint64_t size, long id)
{
	strings_t name = ctf__get32(ctf, &tp->base.ctf_name);
	struct class *fwd = class__new(name, size);

	if (fwd == NULL)
		return -ENOMEM;
	fwd->type.declaration = 1;
	cu__add_tag(ctf->priv, &fwd->type.namespace.tag, &id);
	return 0;
}

static int create_new_typedef(struct ctf *ctf, struct ctf_full_type *tp,
			      uint64_t size, long id)
{
	strings_t name = ctf__get32(ctf, &tp->base.ctf_name);
	unsigned int type_id = ctf__get16(ctf, &tp->base.ctf_type);
	struct type *type = type__new(DW_TAG_typedef, name, size);

	if (type == NULL)
		return -ENOMEM;

	type->namespace.tag.type = type_id;
	cu__add_tag(ctf->priv, &type->namespace.tag, &id);

	return 0;
}

static int create_new_tag(struct ctf *ctf, int type,
			  struct ctf_full_type *tp, long id)
{
	unsigned int type_id = ctf__get16(ctf, &tp->base.ctf_type);
	struct tag *tag = zalloc(sizeof(*tag));

	if (tag == NULL)
		return -ENOMEM;

	switch (type) {
	case CTF_TYPE_KIND_CONST:	tag->tag = DW_TAG_const_type;	 break;
	case CTF_TYPE_KIND_PTR:		tag->tag = DW_TAG_pointer_type;  break;
	case CTF_TYPE_KIND_RESTRICT:	tag->tag = DW_TAG_restrict_type; break;
	case CTF_TYPE_KIND_VOLATILE:	tag->tag = DW_TAG_volatile_type; break;
	default:
		printf("%s: FOO %d\n\n", __func__, type);
		return 0;
	}

	tag->type = type_id;
	cu__add_tag(ctf->priv, tag, &id);

	return 0;
}

static int ctf__load_types(struct ctf *ctf)
{
	void *ctf_buffer = ctf__get_buffer(ctf);
	struct ctf_header *hp = ctf_buffer;
	void *ctf_contents = ctf_buffer + sizeof(*hp),
	     *type_section = (ctf_contents + ctf__get32(ctf, &hp->ctf_type_off)),
	     *strings_section = (ctf_contents + ctf__get32(ctf, &hp->ctf_str_off));
	struct ctf_full_type *type_ptr = type_section,
			     *end = strings_section;
	unsigned int type_index = 0x0001;

	if (hp->ctf_parent_name || hp->ctf_parent_label)
		type_index += 0x8000;

	while (type_ptr < end) {
		uint16_t val	   = ctf__get16(ctf, &type_ptr->base.ctf_info);
		uint16_t type	   = CTF_GET_KIND(val);
		int	 vlen	   = CTF_GET_VLEN(val);
		void	 *ptr	   = type_ptr;
		uint16_t base_size = ctf__get16(ctf, &type_ptr->base.ctf_size);
		uint64_t size	   = base_size;

		if (base_size == 0xffff) {
			size = ctf__get32(ctf, &type_ptr->ctf_size_high);
			size <<= 32;
			size |= ctf__get32(ctf, &type_ptr->ctf_size_low);
			ptr += sizeof(struct ctf_full_type);
		} else
			ptr += sizeof(struct ctf_short_type);

		if (type == CTF_TYPE_KIND_INT) {
			vlen = create_new_base_type(ctf, ptr, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_FLT) {
			vlen = create_new_base_type_float(ctf, ptr, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_ARR) {
			vlen = create_new_array(ctf, ptr, type_index);
		} else if (type == CTF_TYPE_KIND_FUNC) {
			vlen = create_new_subroutine_type(ctf, ptr, vlen, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_STR) {
			vlen = create_new_class(ctf, ptr,
						vlen, type_ptr, size, type_index);
		} else if (type == CTF_TYPE_KIND_UNION) {
			vlen = create_new_union(ctf, ptr,
					        vlen, type_ptr, size, type_index);
		} else if (type == CTF_TYPE_KIND_ENUM) {
			vlen = create_new_enumeration(ctf, ptr, vlen, type_ptr,
						      size, type_index);
		} else if (type == CTF_TYPE_KIND_FWD) {
			vlen = create_new_forward_decl(ctf, type_ptr, size, type_index);
		} else if (type == CTF_TYPE_KIND_TYPDEF) {
			vlen = create_new_typedef(ctf, type_ptr, size, type_index);
		} else if (type == CTF_TYPE_KIND_VOLATILE ||
			   type == CTF_TYPE_KIND_PTR ||
			   type == CTF_TYPE_KIND_CONST ||
			   type == CTF_TYPE_KIND_RESTRICT) {
			vlen = create_new_tag(ctf, type, type_ptr, type_index);
		} else if (type == CTF_TYPE_KIND_UNKN) {
			cu__table_nullify_type_entry(ctf->priv, type_index);
			fprintf(stderr,
				"CTF: idx: %d, off: %zd, root: %s Unknown\n",
				type_index, ((void *)type_ptr) - type_section,
				CTF_ISROOT(val) ? "yes" : "no");
			vlen = 0;
		} else
			return -EINVAL;

		if (vlen < 0)
			return vlen;

		type_ptr = ptr + vlen;
		type_index++;
	}
	return 0;
}

static struct dwvariable *variable__new(uint16_t type, GElf_Sym *sym,
				      struct ctf *ctf)
{
	struct dwvariable *var = tag__alloc(sizeof(*var));

	if (var != NULL) {
		var->location = LOCATION_GLOBAL;
		var->ip.addr = elf_sym__value(sym);
		var->name = sym->st_name;
		var->external = elf_sym__bind(sym) == STB_GLOBAL;
		var->ip.tag.tag = DW_TAG_variable;
		var->ip.tag.type = type;
		long id = -1; /* FIXME: not needed for variables... */
		cu__add_tag(ctf->priv, &var->ip.tag, &id);
	}

	return var;
}

static int ctf__load_objects(struct ctf *ctf)
{
	struct ctf_header *hp = ctf__get_buffer(ctf);
	uint16_t *objp = (ctf__get_buffer(ctf) + sizeof(*hp) +
			  ctf__get32(ctf, &hp->ctf_object_off));

	GElf_Sym sym;
	uint32_t idx;
	ctf__for_each_symtab_object(ctf, idx, sym) {
		const uint16_t type = *objp;
		/*
		 * Discard void objects, probably was an object
		 * we didn't found DWARF info for when encoding.
		 */
		if (type && variable__new(type, &sym, ctf) == NULL)
			return -ENOMEM;
		++objp;
	}

	return 0;
}

static int ctf__load_sections(struct ctf *ctf)
{
	int err = ctf__load_symtab(ctf);

	if (err != 0)
		goto out;
	err = ctf__load_funcs(ctf);
	if (err == 0)
		err = ctf__load_types(ctf);
	if (err == 0)
		err = ctf__load_objects(ctf);
out:
	return err;
}

static int class__fixup_ctf_bitfields(struct tag *tag, struct cu *cu)
{
	struct class_member *pos;
	struct type *tag_type = tag__type(tag);

	type__for_each_data_member(tag_type, pos) {
		struct tag *type = tag__follow_typedef(&pos->tag, cu);

		if (type == NULL) /* FIXME: C++ CTF... */
			continue;

		pos->bitfield_offset = 0;
		pos->bitfield_size = 0;
		pos->byte_offset = pos->bit_offset / 8;

		uint16_t type_bit_size;
		size_t integral_bit_size;

		switch (type->tag) {
		case DW_TAG_enumeration_type:
			type_bit_size = tag__type(type)->size;
			/* Best we can do to check if this is a packed enum */
			if (is_power_of_2(type_bit_size))
				integral_bit_size = roundup(type_bit_size, 8);
			else
				integral_bit_size = sizeof(int) * 8;
			break;
		case DW_TAG_base_type: {
			struct base_type *bt = tag__base_type(type);
			char name[256];
			type_bit_size = bt->bit_size;
			integral_bit_size = base_type__name_to_size(bt, cu);
			if (integral_bit_size == 0)
				fprintf(stderr, "%s: unknown base type name \"%s\"!\n",
					__func__, base_type__name(bt, cu, name,
								  sizeof(name)));
		}
			break;
		default:
			pos->byte_size = tag__size(type, cu);
			pos->bit_size = pos->byte_size * 8;
			continue;
		}

		/*
		 * XXX: integral_bit_size can be zero if base_type__name_to_size doesn't
		 * know about the base_type name, so one has to add there when
		 * such base_type isn't found. pahole will put zero on the
		 * struct output so it should be easy to spot the name when
		 * such unlikely thing happens.
		 */
		pos->byte_size = integral_bit_size / 8;

		if (integral_bit_size == 0 || type_bit_size == integral_bit_size) {
			pos->bit_size = integral_bit_size;
			continue;
		}

		pos->bitfield_offset = pos->bit_offset % integral_bit_size;
		pos->bitfield_size = type_bit_size;
		pos->bit_size = type_bit_size;
		pos->byte_offset = (((pos->bit_offset / integral_bit_size) *
				     integral_bit_size) / 8);
	}

	return 0;
}

static int cu__fixup_ctf_bitfields(struct cu *cu)
{
	int err = 0;
	struct tag *pos;

	list_for_each_entry(pos, &cu->tags, node)
		if (tag__is_struct(pos) || tag__is_union(pos)) {
			err = class__fixup_ctf_bitfields(pos, cu);
			if (err)
				break;
		}

	return err;
}

static const char *ctf__function_name(struct function *func,
				      const struct cu *cu)
{
	struct ctf *ctf = cu->priv;

	return ctf->symtab->symstrs->d_buf + func->name;
}

static const char *ctf__variable_name(const struct dwvariable *var,
				      const struct cu *cu)
{
	struct ctf *ctf = cu->priv;

	return ctf->symtab->symstrs->d_buf + var->name;
}

static void ctf__cu_delete(struct cu *cu)
{
	ctf__delete(cu->priv);
	cu->priv = NULL;
}

static const char *ctf__strings_ptr(const struct cu *cu, strings_t s)
{
	return ctf__string(cu->priv, s);
}

struct debug_fmt_ops ctf__ops;

int ctf__load_file(struct cus *cus, struct conf_load *conf,
		   const char *filename)
{
	int err;
	struct ctf *state = ctf__new(filename, NULL);

	if (state == NULL)
		return -1;

	struct cu *cu = cu__new(filename, state->wordsize, NULL, 0, filename);
	if (cu == NULL)
		return -1;

	cu->language = LANG_C;
	cu->uses_global_strings = false;
	cu->dfops = &ctf__ops;
	cu->priv = state;
	state->priv = cu;
	if (ctf__load(state) != 0)
		return -1;

	err = ctf__load_sections(state);

	if (err != 0) {
		cu__delete(cu);
		return err;
	}

	err = cu__fixup_ctf_bitfields(cu);
	/*
	 * The app stole this cu, possibly deleting it,
	 * so forget about it
	 */
	if (conf && conf->steal && conf->steal(cu, conf))
		return 0;

	cus__add(cus, cu);
	return err;
}

struct debug_fmt_ops ctf__ops = {
	.name		= "ctf",
	.function__name = ctf__function_name,
	.load_file	= ctf__load_file,
	.variable__name = ctf__variable_name,
	.strings__ptr	= ctf__strings_ptr,
	.cu__delete	= ctf__cu_delete,
};
