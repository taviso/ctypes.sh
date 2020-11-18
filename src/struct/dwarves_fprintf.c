/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007..2009 Red Hat Inc.
  Copyright (C) 2007..2009 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

#include <dwarf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <elfutils/version.h>

#include "config.h"
#include "dwarves.h"

static const char *dwarf_tag_names[] = {
	[DW_TAG_array_type]		  = "array_type",
	[DW_TAG_class_type]		  = "class_type",
	[DW_TAG_entry_point]		  = "entry_point",
	[DW_TAG_enumeration_type]	  = "enumeration_type",
	[DW_TAG_formal_parameter]	  = "formal_parameter",
	[DW_TAG_imported_declaration]	  = "imported_declaration",
	[DW_TAG_label]			  = "label",
	[DW_TAG_lexical_block]		  = "lexical_block",
	[DW_TAG_member]			  = "member",
	[DW_TAG_pointer_type]		  = "pointer_type",
	[DW_TAG_reference_type]		  = "reference_type",
	[DW_TAG_compile_unit]		  = "compile_unit",
	[DW_TAG_string_type]		  = "string_type",
	[DW_TAG_structure_type]		  = "structure_type",
	[DW_TAG_subroutine_type]	  = "subroutine_type",
	[DW_TAG_typedef]		  = "typedef",
	[DW_TAG_union_type]		  = "union_type",
	[DW_TAG_unspecified_parameters]	  = "unspecified_parameters",
	[DW_TAG_variant]		  = "variant",
	[DW_TAG_common_block]		  = "common_block",
	[DW_TAG_common_inclusion]	  = "common_inclusion",
	[DW_TAG_inheritance]		  = "inheritance",
	[DW_TAG_inlined_subroutine]	  = "inlined_subroutine",
	[DW_TAG_module]			  = "module",
	[DW_TAG_ptr_to_member_type]	  = "ptr_to_member_type",
	[DW_TAG_set_type]		  = "set_type",
	[DW_TAG_subrange_type]		  = "subrange_type",
	[DW_TAG_with_stmt]		  = "with_stmt",
	[DW_TAG_access_declaration]	  = "access_declaration",
	[DW_TAG_base_type]		  = "base_type",
	[DW_TAG_catch_block]		  = "catch_block",
	[DW_TAG_const_type]		  = "const_type",
	[DW_TAG_constant]		  = "constant",
	[DW_TAG_enumerator]		  = "enumerator",
	[DW_TAG_file_type]		  = "file_type",
	[DW_TAG_friend]			  = "friend",
	[DW_TAG_namelist]		  = "namelist",
	[DW_TAG_namelist_item]		  = "namelist_item",
	[DW_TAG_packed_type]		  = "packed_type",
	[DW_TAG_subprogram]		  = "subprogram",
	[DW_TAG_template_type_parameter]  = "template_type_parameter",
	[DW_TAG_template_value_parameter] = "template_value_parameter",
	[DW_TAG_thrown_type]		  = "thrown_type",
	[DW_TAG_try_block]		  = "try_block",
	[DW_TAG_variant_part]		  = "variant_part",
	[DW_TAG_variable]		  = "variable",
	[DW_TAG_volatile_type]		  = "volatile_type",
	[DW_TAG_dwarf_procedure]	  = "dwarf_procedure",
	[DW_TAG_restrict_type]		  = "restrict_type",
	[DW_TAG_interface_type]		  = "interface_type",
	[DW_TAG_namespace]		  = "namespace",
	[DW_TAG_imported_module]	  = "imported_module",
	[DW_TAG_unspecified_type]	  = "unspecified_type",
	[DW_TAG_partial_unit]		  = "partial_unit",
	[DW_TAG_imported_unit]		  = "imported_unit",
	[DW_TAG_condition]		  = "condition",
	[DW_TAG_shared_type]		  = "shared_type",
#ifdef STB_GNU_UNIQUE
	[DW_TAG_type_unit]		  = "type_unit",
	[DW_TAG_rvalue_reference_type]    = "rvalue_reference_type",
#endif
};

static const char *dwarf_gnu_tag_names[] = {
	[DW_TAG_MIPS_loop - DW_TAG_MIPS_loop]			= "MIPS_loop",
	[DW_TAG_format_label - DW_TAG_MIPS_loop]		= "format_label",
	[DW_TAG_function_template - DW_TAG_MIPS_loop]		= "function_template",
	[DW_TAG_class_template - DW_TAG_MIPS_loop]		= "class_template",
#ifdef STB_GNU_UNIQUE
	[DW_TAG_GNU_BINCL - DW_TAG_MIPS_loop]			= "GNU_BINCL",
	[DW_TAG_GNU_EINCL - DW_TAG_MIPS_loop]			= "GNU_EINCL",
	[DW_TAG_GNU_template_template_param - DW_TAG_MIPS_loop] = "GNU_template_template_param",
	[DW_TAG_GNU_template_parameter_pack - DW_TAG_MIPS_loop] = "GNU_template_parameter_pack",
	[DW_TAG_GNU_formal_parameter_pack - DW_TAG_MIPS_loop]	= "GNU_formal_parameter_pack",
#endif
#if _ELFUTILS_PREREQ(0, 153)
	[DW_TAG_GNU_call_site - DW_TAG_MIPS_loop]		= "GNU_call_site",
	[DW_TAG_GNU_call_site_parameter - DW_TAG_MIPS_loop]	= "GNU_call_site_parameter",
#endif
};

const char *dwarf_tag_name(const uint32_t tag)
{
	if (tag >= DW_TAG_array_type && tag <=
#ifdef STB_GNU_UNIQUE
		DW_TAG_rvalue_reference_type
#else
		DW_TAG_shared_type
#endif
	    )
		return dwarf_tag_names[tag];
	else if (tag >= DW_TAG_MIPS_loop && tag <=
#if _ELFUTILS_PREREQ(0, 153)
	         DW_TAG_GNU_call_site_parameter
#elif STB_GNU_UNIQUE
		 DW_TAG_GNU_formal_parameter_pack
#else
		 DW_TAG_class_template
#endif
		)
		return dwarf_gnu_tag_names[tag - DW_TAG_MIPS_loop];
	return "INVALID";
}

static const struct conf_fprintf conf_fprintf__defaults = {
	.name_spacing = 23,
	.type_spacing = 26,
	.emit_stats   = 1,
};

static const char tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

static size_t cacheline_size;

size_t tag__nr_cachelines(const struct tag *tag, const struct cu *cu)
{
	return (tag__size(tag, cu) + cacheline_size - 1) / cacheline_size;
}

static const char *tag__accessibility(const struct tag *tag)
{
	int a;

	switch (tag->tag) {
	case DW_TAG_inheritance:
	case DW_TAG_member:
		a = tag__class_member(tag)->accessibility;
		break;
	case DW_TAG_subprogram:
		a = tag__function(tag)->accessibility;
		break;
	default:
		return NULL;
	}

	switch (a) {
	case DW_ACCESS_public:	  return "public";
	case DW_ACCESS_private:	  return "private";
	case DW_ACCESS_protected: return "protected";
	}

	return NULL;
}

static size_t __tag__id_not_found_snprintf(char *bf, size_t len, uint32_t id,
					   const char *fn, int line)
{
	return snprintf(bf, len, "<ERROR(%s:%d): %#llx not found!>", fn, line,
			(unsigned long long)id);
}

#define tag__id_not_found_snprintf(bf, len, id) \
	__tag__id_not_found_snprintf(bf, len, id, __func__, __LINE__)

size_t tag__fprintf_decl_info(const struct tag *tag,
			      const struct cu *cu, FILE *fp)
{
	return fprintf(fp, "/* <%llx> %s:%u */\n", tag__orig_id(tag, cu),
		       tag__decl_file(tag, cu), tag__decl_line(tag, cu));
	return 0;
}

static size_t type__fprintf(struct tag *type, const struct cu *cu,
			    const char *name, const struct conf_fprintf *conf,
			    FILE *fp);

static size_t array_type__fprintf(const struct tag *tag,
				  const struct cu *cu, const char *name,
				  const struct conf_fprintf *conf,
				  FILE *fp)
{
	struct array_type *at = tag__array_type(tag);
	struct tag *type = cu__type(cu, tag->type);
	size_t printed;
	unsigned long long flat_dimensions = 0;
	int i;

	if (type == NULL)
		return tag__id_not_found_fprintf(fp, tag->type);

	/* Zero sized arrays? */
	if (at->dimensions >= 1 && at->nr_entries[0] == 0 && tag__is_const(type))
		type = cu__type(cu, type->type);

	printed = type__fprintf(type, cu, name, conf, fp);
	for (i = 0; i < at->dimensions; ++i) {
		if (conf->flat_arrays || at->is_vector) {
			/*
			 * Seen on the Linux kernel on tun_filter:
			 *
			 * __u8   addr[0][ETH_ALEN];
			 */
			if (at->nr_entries[i] == 0 && i == 0)
				break;
			if (!flat_dimensions)
				flat_dimensions = at->nr_entries[i];
			else
				flat_dimensions *= at->nr_entries[i];
		} else {
			bool single_member = conf->last_member && conf->first_member;

			if (at->nr_entries[i] != 0 || !conf->last_member || single_member || conf->union_member)
				printed += fprintf(fp, "[%u]", at->nr_entries[i]);
			else
				printed += fprintf(fp, "[]");
		}
	}

	if (at->is_vector) {
		type = tag__follow_typedef(tag, cu);

		if (flat_dimensions == 0)
			flat_dimensions = 1;
		printed += fprintf(fp, " __attribute__ ((__vector_size__ (%llu)))",
				   flat_dimensions * tag__size(type, cu));
	} else if (conf->flat_arrays) {
		bool single_member = conf->last_member && conf->first_member;

		if (flat_dimensions != 0 || !conf->last_member || single_member || conf->union_member)
			printed += fprintf(fp, "[%llu]", flat_dimensions);
		else
			printed += fprintf(fp, "[]");
	}

	return printed;
}

size_t typedef__fprintf(const struct tag *tag, const struct cu *cu,
			const struct conf_fprintf *conf, FILE *fp)
{
	struct type *type = tag__type(tag);
	const struct conf_fprintf *pconf = conf ?: &conf_fprintf__defaults;
	const struct tag *tag_type;
	const struct tag *ptr_type;
	char bf[512];
	int is_pointer = 0;
	size_t printed;

	/*
	 * Check for void (humm, perhaps we should have a fake void tag instance
	 * to avoid all these checks?
	 */
	if (tag->type == 0)
		return fprintf(fp, "typedef void %s", type__name(type, cu));

	tag_type = cu__type(cu, tag->type);
	if (tag_type == NULL) {
		printed = fprintf(fp, "typedef ");
		printed += tag__id_not_found_fprintf(fp, tag->type);
		return printed + fprintf(fp, " %s", type__name(type, cu));
	}

	switch (tag_type->tag) {
	case DW_TAG_array_type:
		printed = fprintf(fp, "typedef ");
		return printed + array_type__fprintf(tag_type, cu,
						     type__name(type, cu),
						     pconf, fp);
	case DW_TAG_pointer_type:
		if (tag_type->type == 0) /* void pointer */
			break;
		ptr_type = cu__type(cu, tag_type->type);
		if (ptr_type == NULL) {
			printed = fprintf(fp, "typedef ");
			printed += tag__id_not_found_fprintf(fp, tag_type->type);
			return printed + fprintf(fp, " *%s",
						 type__name(type, cu));
		}
		if (ptr_type->tag != DW_TAG_subroutine_type)
			break;
		tag_type = ptr_type;
		is_pointer = 1;
		/* Fall thru */
	case DW_TAG_subroutine_type:
		printed = fprintf(fp, "typedef ");
		return printed + ftype__fprintf(tag__ftype(tag_type), cu,
						type__name(type, cu),
						0, is_pointer, 0,
						true, pconf, fp);
	case DW_TAG_class_type:
	case DW_TAG_structure_type: {
		struct type *ctype = tag__type(tag_type);

		if (type__name(ctype, cu) != NULL)
			return fprintf(fp, "typedef struct %s %s",
				       type__name(ctype, cu),
				       type__name(type, cu));
	}
	}

	return fprintf(fp, "typedef %s %s",
		       tag__name(tag_type, cu, bf, sizeof(bf), pconf),
				 type__name(type, cu));
}

static size_t imported_declaration__fprintf(const struct tag *tag,
					    const struct cu *cu, FILE *fp)
{
	char bf[BUFSIZ];
	size_t printed = fprintf(fp, "using ::");
	const struct tag *decl = cu__function(cu, tag->type);

	if (decl == NULL) {
		decl = cu__tag(cu, tag->type);
		if (decl == NULL)
			return printed + tag__id_not_found_fprintf(fp, tag->type);
	}

	return printed + fprintf(fp, "%s", tag__name(decl, cu, bf, sizeof(bf), NULL));
}

static size_t imported_module__fprintf(const struct tag *tag,
				       const struct cu *cu, FILE *fp)
{
	const struct tag *module = cu__tag(cu, tag->type);
	const char *name = "<IMPORTED MODULE ERROR!>";

	if (tag__is_namespace(module))
		name = namespace__name(tag__namespace(module), cu);

	return fprintf(fp, "using namespace %s", name);
}

size_t enumeration__fprintf(const struct tag *tag, const struct cu *cu,
			    const struct conf_fprintf *conf, FILE *fp)
{
	struct type *type = tag__type(tag);
	struct enumerator *pos;
	size_t printed = fprintf(fp, "enum%s%s {\n",
				 type__name(type, cu) ? " " : "",
				 type__name(type, cu) ?: "");
	int indent = conf->indent;

	if (indent >= (int)sizeof(tabs))
		indent = sizeof(tabs) - 1;

	type__for_each_enumerator(type, pos)
		printed += fprintf(fp, "%.*s\t%s = %u,\n", indent, tabs,
				   enumerator__name(pos, cu), pos->value);

	printed += fprintf(fp, "%.*s}", indent, tabs);

	/*
	 * XXX: find out how to precisely determine the max size for an
	 * enumeration, use sizeof(int) for now.
	 */
	if (type->size / 8 != sizeof(int))
		printed += fprintf(fp, " %s", "__attribute__((__packed__))");

	if (conf->suffix)
		printed += fprintf(fp, " %s", conf->suffix);

	return printed;
}

static const char *tag__prefix(const struct cu *cu, const uint32_t tag,
			       const struct conf_fprintf *conf)
{
	switch (tag) {
	case DW_TAG_enumeration_type:	return "enum ";
	case DW_TAG_structure_type:
		return (!conf->classes_as_structs &&
			cu->language == DW_LANG_C_plus_plus) ? "class " :
							       "struct ";
	case DW_TAG_class_type:
		return conf->classes_as_structs ? "struct " : "class ";
	case DW_TAG_union_type:		return "union ";
	case DW_TAG_pointer_type:	return " *";
	case DW_TAG_reference_type:	return " &";
	}

	return "";
}

static const char *__tag__name(const struct tag *tag, const struct cu *cu,
			       char *bf, size_t len,
			       const struct conf_fprintf *conf);

static const char *tag__ptr_name(const struct tag *tag, const struct cu *cu,
				 char *bf, size_t len, const char *ptr_suffix)
{
	if (tag->type == 0) /* No type == void */
		snprintf(bf, len, "void %s", ptr_suffix);
	else {
		const struct tag *type = cu__type(cu, tag->type);

		if (type == NULL) {
			size_t l = tag__id_not_found_snprintf(bf, len, tag->type);
			snprintf(bf + l, len - l, " %s", ptr_suffix);
		} else if (!tag__has_type_loop(tag, type, bf, len, NULL)) {
			char tmpbf[1024];
			const char *const_pointer = "";

			if (tag__is_const(type)) {
				struct tag *next_type = cu__type(cu, type->type);

				if (next_type && tag__is_pointer(next_type)) {
					const_pointer = "const ";
					type = next_type;
				}
			}

			snprintf(bf, len, "%s %s%s",
				 __tag__name(type, cu,
					     tmpbf, sizeof(tmpbf), NULL),
				 const_pointer,
				 ptr_suffix);
		}
	}

	return bf;
}

static const char *__tag__name(const struct tag *tag, const struct cu *cu,
			       char *bf, size_t len,
			       const struct conf_fprintf *conf)
{
	struct tag *type;
	const struct conf_fprintf *pconf = conf ?: &conf_fprintf__defaults;

	if (tag == NULL)
		strncpy(bf, "void", len);
	else switch (tag->tag) {
	case DW_TAG_base_type: {
		const struct base_type *bt = tag__base_type(tag);
		const char *name = "nameless base type!";
		char bf2[64];

		if (bt->name)
			name = base_type__name(tag__base_type(tag), cu,
					       bf2, sizeof(bf2));

		strncpy(bf, name, len);
	}
		break;
	case DW_TAG_subprogram:
		strncpy(bf, function__name(tag__function(tag), cu), len);
		break;
	case DW_TAG_pointer_type:
		return tag__ptr_name(tag, cu, bf, len, "*");
	case DW_TAG_reference_type:
		return tag__ptr_name(tag, cu, bf, len, "&");
	case DW_TAG_ptr_to_member_type: {
		char suffix[512];
		type_id_t id = tag__ptr_to_member_type(tag)->containing_type;

		type = cu__type(cu, id);
		if (type != NULL)
			snprintf(suffix, sizeof(suffix), "%s::*",
				 class__name(tag__class(type), cu));
		else {
			size_t l = tag__id_not_found_snprintf(suffix,
							      sizeof(suffix),
							      id);
			snprintf(suffix + l, sizeof(suffix) - l, "::*");
		}

		return tag__ptr_name(tag, cu, bf, len, suffix);
	}
	case DW_TAG_volatile_type:
	case DW_TAG_const_type:
	case DW_TAG_restrict_type:
	case DW_TAG_unspecified_type:
		type = cu__type(cu, tag->type);
		if (type == NULL && tag->type != 0)
			tag__id_not_found_snprintf(bf, len, tag->type);
		else if (!tag__has_type_loop(tag, type, bf, len, NULL)) {
			char tmpbf[128];
			const char *prefix = "", *suffix = "",
				   *type_str = __tag__name(type, cu, tmpbf,
							   sizeof(tmpbf),
							   pconf);
			switch (tag->tag) {
			case DW_TAG_volatile_type: prefix = "volatile "; break;
			case DW_TAG_const_type:    prefix = "const ";	 break;
			case DW_TAG_restrict_type: suffix = " restrict"; break;
			}
			snprintf(bf, len, "%s%s%s ", prefix, type_str, suffix);
		}
		break;
	case DW_TAG_array_type:
		type = cu__type(cu, tag->type);
		if (type == NULL)
			tag__id_not_found_snprintf(bf, len, tag->type);
		else if (!tag__has_type_loop(tag, type, bf, len, NULL))
			return __tag__name(type, cu, bf, len, pconf);
		break;
	case DW_TAG_subroutine_type: {
		FILE *bfp = fmemopen(bf, len, "w");

		if (bfp != NULL) {
			ftype__fprintf(tag__ftype(tag), cu, NULL, 0, 0, 0, true, pconf, bfp);
			fclose(bfp);
		} else
			snprintf(bf, len, "<ERROR(%s): fmemopen failed!>",
				 __func__);
	}
		break;
	case DW_TAG_member:
		snprintf(bf, len, "%s", class_member__name(tag__class_member(tag), cu));
		break;
	case DW_TAG_variable:
		snprintf(bf, len, "%s", variable__name(tag__variable(tag), cu));
		break;
	default:
		snprintf(bf, len, "%s%s", tag__prefix(cu, tag->tag, pconf),
			 type__name(tag__type(tag), cu) ?: "");
		break;
	}

	return bf;
}

const char *tag__name(const struct tag *tag, const struct cu *cu,
		      char *bf, size_t len, const struct conf_fprintf *conf)
{
	int printed = 0;

	if (tag == NULL) {
		strncpy(bf, "void", len);
		return bf;
	}

	__tag__name(tag, cu, bf + printed, len - printed, conf);

	return bf;
}

static const char *variable__prefix(const struct dw_variable *var)
{
	switch (variable__scope(var)) {
	case VSCOPE_REGISTER:
		return "register ";
	case VSCOPE_UNKNOWN:
		if (var->external && var->declaration)
			return "extern ";
		break;
	case VSCOPE_GLOBAL:
		if (!var->external)
			return "static ";
		break;
	case VSCOPE_LOCAL:
	case VSCOPE_OPTIMIZED:
		break;
	}
	return NULL;
}

static size_t type__fprintf_stats(struct type *type, const struct cu *cu,
				  const struct conf_fprintf *conf, FILE *fp)
{
	size_t printed = fprintf(fp, "\n%.*s/* size: %d, cachelines: %zd, members: %u",
				 conf->indent, tabs, type->size,
				 tag__nr_cachelines(type__tag(type), cu), type->nr_members);

	if (type->nr_static_members != 0)
		printed += fprintf(fp, ", static members: %u */\n", type->nr_static_members);
	else
		printed += fprintf(fp, " */\n");

	return printed;
}

static size_t union__fprintf(struct type *type, const struct cu *cu,
			     const struct conf_fprintf *conf, FILE *fp);

static size_t __class__fprintf(struct class *class, const struct cu *cu,
			       const struct conf_fprintf *conf, FILE *fp);

static size_t type__fprintf(struct tag *type, const struct cu *cu,
			    const char *name, const struct conf_fprintf *conf,
			    FILE *fp)
{
	char tbf[128];
	char namebf[256];
	char namebfptr[258];
	struct type *ctype;
	struct tag *type_expanded = NULL;
	struct conf_fprintf tconf = {
		.type_spacing = conf->type_spacing,
	};
	size_t printed = 0;
	int expand_types = conf->expand_types;
	int suppress_offset_comment = conf->suppress_offset_comment;

	if (type == NULL)
		goto out_type_not_found;

	if (conf->expand_pointers) {
		int nr_indirections = 0;

		while (tag__is_pointer(type) && type->type != 0) {
			struct tag *ttype = cu__type(cu, type->type);
			if (ttype == NULL)
				goto out_type_not_found;
			else {
				printed = tag__has_type_loop(type, ttype,
							     NULL, 0, fp);
				if (printed)
					return printed;
			}
			type = ttype;
			++nr_indirections;
		}

		if (nr_indirections > 0) {
			const size_t len = strlen(name);
			if (len + nr_indirections >= sizeof(namebf))
				goto out_type_not_found;
			memset(namebf, '*', nr_indirections);
			memcpy(namebf + nr_indirections, name, len);
			namebf[len + nr_indirections] = '\0';
			name = namebf;
		}

		expand_types = nr_indirections;
		if (!suppress_offset_comment)
			suppress_offset_comment = !!nr_indirections;

		/* Avoid loops */
		if (type->recursivity_level != 0)
			expand_types = 0;
		++type->recursivity_level;
		type_expanded = type;
	}

	if (expand_types) {
		int typedef_expanded = 0;

		while (tag__is_typedef(type)) {
			struct tag *type_type;
			int n;

			ctype = tag__type(type);
			if (typedef_expanded)
				printed += fprintf(fp, " -> %s",
						   type__name(ctype, cu));
			else {
				printed += fprintf(fp, "/* typedef %s",
						   type__name(ctype, cu));
				typedef_expanded = 1;
			}
			type_type = cu__type(cu, type->type);
			if (type_type == NULL)
				goto out_type_not_found;
			n = tag__has_type_loop(type, type_type, NULL, 0, fp);
			if (n)
				return printed + n;
			type = type_type;
		}
		if (typedef_expanded)
			printed += fprintf(fp, " */ ");
	}

	tconf = *conf;

	if (tag__is_struct(type) || tag__is_union(type) ||
	    tag__is_enumeration(type)) {
inner_struct:
		tconf.prefix	   = NULL;
		tconf.suffix	   = name;
		tconf.emit_stats   = 0;
		tconf.suppress_offset_comment = suppress_offset_comment;
	}

next_type:
	switch (type->tag) {
	case DW_TAG_pointer_type:
		if (type->type != 0) {
			int n;
			struct tag *ptype = cu__type(cu, type->type);
			if (ptype == NULL)
				goto out_type_not_found;
			n = tag__has_type_loop(type, ptype, NULL, 0, fp);
			if (n)
				return printed + n;
			if (ptype->tag == DW_TAG_subroutine_type) {
				printed += ftype__fprintf(tag__ftype(ptype),
							  cu, name, 0, 1,
							  tconf.type_spacing, true,
							  &tconf, fp);
				break;
			}
			if ((tag__is_struct(ptype) || tag__is_union(ptype) ||
			    tag__is_enumeration(ptype)) && type__name(tag__type(ptype), cu) == NULL) {
				if (name == namebfptr)
					goto out_type_not_found;
				snprintf(namebfptr, sizeof(namebfptr), "* %.*s", (int)sizeof(namebfptr) - 3, name);
				tconf.rel_offset = 1;
				name = namebfptr;
				type = ptype;
				tconf.type_spacing -= 8;
				goto inner_struct;
			}
		}
		/* Fall Thru */
	default:
print_default:
		printed += fprintf(fp, "%-*s %s", tconf.type_spacing,
				   tag__name(type, cu, tbf, sizeof(tbf), &tconf),
				   name);
		break;
	case DW_TAG_subroutine_type:
		printed += ftype__fprintf(tag__ftype(type), cu, name, 0, 0,
					  tconf.type_spacing, true, &tconf, fp);
		break;
	case DW_TAG_const_type: {
		size_t const_printed = fprintf(fp, "%s ", "const");
		tconf.type_spacing -= const_printed;
		printed		   += const_printed;

		struct tag *ttype = cu__type(cu, type->type);
		if (ttype) {
			type = ttype;
			goto next_type;
		}
	}
		goto print_default;

	case DW_TAG_array_type:
		printed += array_type__fprintf(type, cu, name, &tconf, fp);
		break;
	case DW_TAG_class_type:
	case DW_TAG_structure_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL && !expand_types) {
			printed += fprintf(fp, "%s %-*s %s",
					   (type->tag == DW_TAG_class_type &&
					    !tconf.classes_as_structs) ? "class" : "struct",
					   tconf.type_spacing - 7,
					   type__name(ctype, cu), name);
		} else {
			struct class *cclass = tag__class(type);

			if (!tconf.suppress_comments)
				class__find_holes(cclass);

			tconf.type_spacing -= 8;
			printed += __class__fprintf(cclass, cu, &tconf, fp);
		}
		break;
	case DW_TAG_union_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL && !expand_types) {
			printed += fprintf(fp, "union %-*s %s",
					   tconf.type_spacing - 6,
					   type__name(ctype, cu), name);
		} else {
			tconf.type_spacing -= 8;
			printed += union__fprintf(ctype, cu, &tconf, fp);
		}
		break;
	case DW_TAG_enumeration_type:
		ctype = tag__type(type);

		if (type__name(ctype, cu) != NULL)
			printed += fprintf(fp, "enum %-*s %s",
					   tconf.type_spacing - 5,
					   type__name(ctype, cu), name);
		else
			printed += enumeration__fprintf(type, cu, &tconf, fp);
		break;
	}
out:
	if (type_expanded)
		--type_expanded->recursivity_level;

	return printed;
out_type_not_found:
	printed = fprintf(fp, "%-*s%s> %s", tconf.type_spacing, "<ERROR",
			  name == namebfptr ? ": pointer to pointer to inner struct/union/enum?" : "", name);
	goto out;
}

static size_t class__fprintf_cacheline_boundary(struct conf_fprintf *conf,
						uint32_t offset,
						FILE *fp);

static size_t class_member__fprintf(struct class_member *member, bool union_member,
				     struct tag *type, const struct cu *cu,
				     struct conf_fprintf *conf, FILE *fp)
{
	const int size = member->byte_size;
	struct conf_fprintf sconf = *conf;
	uint32_t offset = member->byte_offset;
	size_t printed = 0, printed_cacheline = 0;
	const char *cm_name = class_member__name(member, cu),
		   *name = cm_name;

	if (!sconf.rel_offset) {
		offset += sconf.base_offset;
		if (!union_member)
			sconf.base_offset = offset;
	}

	if (member->bitfield_offset < 0)
		offset += member->byte_size;

	if (!conf->suppress_comments)
		printed_cacheline = class__fprintf_cacheline_boundary(conf, offset, fp);

	if (member->tag.tag == DW_TAG_inheritance) {
		name = "<ancestor>";
		printed += fprintf(fp, "/* ");
	}

	if (member->is_static)
		printed += fprintf(fp, "static ");

	printed += type__fprintf(type, cu, name, &sconf, fp);

	if (member->is_static) {
		if (member->const_value != 0)
			printed += fprintf(fp, " = %" PRIu64, member->const_value);
	} else if (member->bitfield_size != 0) {
		printed += fprintf(fp, ":%u", member->bitfield_size);
	}

	if (!sconf.suppress_aligned_attribute && member->alignment != 0)
		printed += fprintf(fp, " __attribute__((__aligned__(%u)))", member->alignment);

	fputc(';', fp);
	++printed;

	if ((tag__is_union(type) || tag__is_struct(type) ||
	     tag__is_enumeration(type)) &&
		/* Look if is a type defined inline */
	    type__name(tag__type(type), cu) == NULL) {
		if (!sconf.suppress_offset_comment) {
			/* Check if this is a anonymous union */
			int slen = cm_name ? (int)strlen(cm_name) : -1;
			int size_spacing = 5;

			if (tag__is_struct(type) && tag__class(type)->is_packed && !conf->suppress_packed) {
				int packed_len = sizeof("__attribute__((__packed__))");
				slen += packed_len;
			}

			if (tag__type(type)->alignment != 0 && !conf->suppress_aligned_attribute) {
				char bftmp[64];
				int aligned_len = snprintf(bftmp, sizeof(bftmp), " __attribute__((__aligned__(%u)))", tag__type(type)->alignment);
				slen += aligned_len;
			}

			printed += fprintf(fp, sconf.hex_fmt ?
							"%*s/* %#5x" :
							"%*s/* %5u",
					   (sconf.type_spacing +
					    sconf.name_spacing - slen - 3),
					   " ", offset);

			if (member->bitfield_size != 0) {
				unsigned int bitfield_offset = member->bitfield_offset;

				if (member->bitfield_offset < 0)
					bitfield_offset = member->byte_size * 8 + member->bitfield_offset;

				printed += fprintf(fp, sconf.hex_fmt ?  ":%#2x" : ":%2u", bitfield_offset);
				size_spacing -= 3;
			}

			printed += fprintf(fp, sconf.hex_fmt ?  " %#*x */" : " %*u */", size_spacing, size);
		}
	} else {
		int spacing = sconf.type_spacing + sconf.name_spacing - printed;

		if (member->tag.tag == DW_TAG_inheritance) {
			const size_t p = fprintf(fp, " */");
			printed += p;
			spacing -= p;
		}
		if (!sconf.suppress_offset_comment) {
			int size_spacing = 5;

			printed += fprintf(fp, sconf.hex_fmt ?
						"%*s/* %#5x" : "%*s/* %5u",
					   spacing > 0 ? spacing : 0, " ",
					   offset);

			if (member->bitfield_size != 0) {
				unsigned int bitfield_offset = member->bitfield_offset;

				if (member->bitfield_offset < 0)
					bitfield_offset = member->byte_size * 8 + member->bitfield_offset;

				printed += fprintf(fp, sconf.hex_fmt ?
							":%#2x" : ":%2u",
						   bitfield_offset);
				size_spacing -= 3;
			}

			printed += fprintf(fp, sconf.hex_fmt ?
						" %#*x */" : " %*u */",
					   size_spacing, size);
		}
	}
	return printed + printed_cacheline;
}

static size_t struct_member__fprintf(struct class_member *member,
				     struct tag *type, const struct cu *cu,
				     struct conf_fprintf *conf, FILE *fp)
{
	return class_member__fprintf(member, false, type, cu, conf, fp);
}

static size_t union_member__fprintf(struct class_member *member,
				    struct tag *type, const struct cu *cu,
				    struct conf_fprintf *conf, FILE *fp)
{
	return class_member__fprintf(member, true, type, cu, conf, fp);
}

static size_t union__fprintf(struct type *type, const struct cu *cu,
			     const struct conf_fprintf *conf, FILE *fp)
{
	struct class_member *pos;
	size_t printed = 0;
	int indent = conf->indent;
	struct conf_fprintf uconf;
	uint32_t initial_union_cacheline;
	uint32_t cacheline = 0; /* This will only be used if this is the outermost union */

	if (indent >= (int)sizeof(tabs))
		indent = sizeof(tabs) - 1;

	if (conf->prefix != NULL)
		printed += fprintf(fp, "%s ", conf->prefix);
	printed += fprintf(fp, "union%s%s {\n", type__name(type, cu) ? " " : "",
			   type__name(type, cu) ?: "");

	uconf = *conf;
	uconf.indent = indent + 1;

	/*
	 * If structs embedded in unions, nameless or not, have a size which isn't
	 * isn't a multiple of the union size, then it must be packed, even if
	 * it has no holes nor padding, as an array of such unions would have the
	 * natural alignments of non-multiple structs inside it broken.
	 */
	union__infer_packed_attributes(type, cu);

	/*
	 * We may be called directly or from tag__fprintf, so keep sure
	 * we keep track of the cacheline we're in.
	 *
	 * If we're being called from an outer structure, i.e. union within
	 * struct, class or another union, then this will already have a
	 * value and we'll continue to use it.
	 */
	if (uconf.cachelinep == NULL)
                uconf.cachelinep = &cacheline;
	/*
	 * Save the cacheline we're in, then, after each union member, get
	 * back to it. Else we'll end up showing cacheline boundaries in
	 * just the first of a multi struct union, for instance.
	 */
	initial_union_cacheline = *uconf.cachelinep;
	type__for_each_member(type, pos) {
		struct tag *pos_type = cu__type(cu, pos->tag.type);

		if (pos_type == NULL) {
			printed += fprintf(fp, "%.*s", uconf.indent, tabs);
			printed += tag__id_not_found_fprintf(fp, pos->tag.type);
			continue;
		}

		uconf.union_member = 1;
		printed += fprintf(fp, "%.*s", uconf.indent, tabs);
		printed += union_member__fprintf(pos, pos_type, cu, &uconf, fp);
		fputc('\n', fp);
		++printed;
		*uconf.cachelinep = initial_union_cacheline;
	}

	return printed + fprintf(fp, "%.*s}%s%s", indent, tabs,
				 conf->suffix ? " " : "", conf->suffix ?: "");
}

const char *function__prototype(const struct function *func,
				const struct cu *cu, char *bf, size_t len)
{
	FILE *bfp = fmemopen(bf, len, "w");

	if (bfp != NULL) {
		ftype__fprintf(&func->proto, cu, NULL, 0, 0, 0, true,
			       &conf_fprintf__defaults, bfp);
		fclose(bfp);
	} else
		snprintf(bf, len, "<ERROR(%s): fmemopen failed!>", __func__);

	return bf;
}

size_t ftype__fprintf_parms(const struct ftype *ftype,
			    const struct cu *cu, int indent,
			    const struct conf_fprintf *conf, FILE *fp)
{
	struct parameter *pos;
	int first_parm = 1;
	char sbf[128];
	struct tag *type;
	const char *name, *stype;
	size_t printed = fprintf(fp, "(");

	ftype__for_each_parameter(ftype, pos) {
		if (!first_parm) {
			if (indent == 0)
				printed += fprintf(fp, ", ");
			else
				printed += fprintf(fp, ",\n%.*s",
						   indent, tabs);
		} else
			first_parm = 0;
		name = conf->no_parm_names ? NULL : parameter__name(pos, cu);
		type = cu__type(cu, pos->tag.type);
		if (type == NULL) {
			snprintf(sbf, sizeof(sbf),
				 "<ERROR: type %d not found>", pos->tag.type);
			stype = sbf;
			goto print_it;
		}
		if (tag__is_pointer(type)) {
			if (type->type != 0) {
				int n;
				struct tag *ptype = cu__type(cu, type->type);
				if (ptype == NULL) {
					printed +=
					    tag__id_not_found_fprintf(fp, type->type);
					continue;
				}
				n = tag__has_type_loop(type, ptype, NULL, 0, fp);
				if (n)
					return printed + n;
				if (ptype->tag == DW_TAG_subroutine_type) {
					printed +=
					     ftype__fprintf(tag__ftype(ptype),
							    cu, name, 0, 1, 0,
							    true, conf, fp);
					continue;
				}
			}
		} else if (type->tag == DW_TAG_subroutine_type) {
			printed += ftype__fprintf(tag__ftype(type), cu, name,
						  true, 0, 0, 0, conf, fp);
			continue;
		}
		stype = tag__name(type, cu, sbf, sizeof(sbf), conf);
print_it:
		printed += fprintf(fp, "%s%s%s", stype, name ? " " : "",
				   name ?: "");
	}

	/* No parameters? */
	if (first_parm)
		printed += fprintf(fp, "void)");
	else if (ftype->unspec_parms)
		printed += fprintf(fp, ", ...)");
	else
		printed += fprintf(fp, ")");
	return printed;
}

static size_t function__tag_fprintf(const struct tag *tag, const struct cu *cu,
				    struct function *function, uint16_t indent,
				    const struct conf_fprintf *conf, FILE *fp)
{
	char bf[512];
	size_t printed = 0, n;
	const void *vtag = tag;
	int c;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;
	c = indent * 8;

	switch (tag->tag) {
	case DW_TAG_inlined_subroutine: {
		const struct inline_expansion *exp = vtag;
		const struct tag *talias = cu__function(cu, exp->ip.tag.type);
		struct function *alias = tag__function(talias);
		const char *name;

		if (alias == NULL) {
			printed += tag__id_not_found_fprintf(fp, exp->ip.tag.type);
			break;
		}
		printed = fprintf(fp, "%.*s", indent, tabs);
		name = function__name(alias, cu);
		n = fprintf(fp, "%s", name);
		size_t namelen = 0;
		if (name != NULL)
			namelen = strlen(name);
		n += ftype__fprintf_parms(&alias->proto, cu,
					  indent + (namelen + 7) / 8,
					  conf, fp);
		n += fprintf(fp, "; /* size=%zd, low_pc=%#llx */",
			     exp->size, (unsigned long long)exp->ip.addr);
#if 0
		n = fprintf(fp, "%s(); /* size=%zd, low_pc=%#llx */",
			    function__name(alias, cu), exp->size,
			    (unsigned long long)exp->ip.addr);
#endif
		c = 69;
		printed += n;
	}
		break;
	case DW_TAG_variable:
		printed = fprintf(fp, "%.*s", indent, tabs);
		n = fprintf(fp, "%s %s; /* scope: %s */",
			    variable__type_name(vtag, cu, bf, sizeof(bf)),
			    variable__name(vtag, cu),
			    variable__scope_str(vtag));
		c += n;
		printed += n;
		break;
	case DW_TAG_label: {
		const struct label *label = vtag;
		printed = fprintf(fp, "%.*s", indent, tabs);
		fputc('\n', fp);
		++printed;
		c = fprintf(fp, "%s:", label__name(label, cu));
		printed += c;
	}
		break;
	case DW_TAG_lexical_block:
		printed = lexblock__fprintf(vtag, cu, function, indent,
					    conf, fp);
		fputc('\n', fp);
		return printed + 1;
	default:
		printed = fprintf(fp, "%.*s", indent, tabs);
		n = fprintf(fp, "%s <%llx>", dwarf_tag_name(tag->tag),
			    tag__orig_id(tag, cu));
		c += n;
		printed += n;
		break;
	}
	return printed + fprintf(fp, "%-*.*s// %5u\n", 70 - c, 70 - c, " ",
				 tag__decl_line(tag, cu));
}

size_t lexblock__fprintf(const struct lexblock *block, const struct cu *cu,
			 struct function *function, uint16_t indent,
			 const struct conf_fprintf *conf, FILE *fp)
{
	struct tag *pos;
	size_t printed;

	if (indent >= sizeof(tabs))
		indent = sizeof(tabs) - 1;
	printed = fprintf(fp, "%.*s{", indent, tabs);
	if (block->ip.addr != 0) {
		uint64_t offset = block->ip.addr - function->lexblock.ip.addr;

		if (offset == 0)
			printed += fprintf(fp, " /* low_pc=%#llx */",
					   (unsigned long long)block->ip.addr);
		else
			printed += fprintf(fp, " /* %s+%#llx */",
					   function__name(function, cu),
					   (unsigned long long)offset);
	}
	printed += fprintf(fp, "\n");
	list_for_each_entry(pos, &block->tags, node)
		printed += function__tag_fprintf(pos, cu, function, indent + 1,
						 conf, fp);
	printed += fprintf(fp, "%.*s}", indent, tabs);

	if (function->lexblock.ip.addr != block->ip.addr)
		printed += fprintf(fp, " /* lexblock size=%d */", block->size);

	return printed;
}

size_t ftype__fprintf(const struct ftype *ftype, const struct cu *cu,
		      const char *name, const int inlined,
		      const int is_pointer, int type_spacing, bool is_prototype,
		      const struct conf_fprintf *conf, FILE *fp)
{
	struct tag *type = cu__type(cu, ftype->tag.type);
	char sbf[128];
	const char *stype = tag__name(type, cu, sbf, sizeof(sbf), conf);
	size_t printed = fprintf(fp, "%s%-*s %s%s%s%s",
				 inlined ? "inline " : "",
				 type_spacing, stype,
				 is_prototype ?  "(" : "",
				 is_pointer ? "*" : "", name ?: "",
				 is_prototype ?  ")" : "");

	return printed + ftype__fprintf_parms(ftype, cu, 0, conf, fp);
}

static size_t function__fprintf(const struct tag *tag, const struct cu *cu,
				const struct conf_fprintf *conf, FILE *fp)
{
	struct function *func = tag__function(tag);
	struct ftype *ftype = func->btf ? tag__ftype(cu__type(cu, func->proto.tag.type)) : &func->proto;
	size_t printed = 0;
	bool inlined = !conf->strip_inline && function__declared_inline(func);

	if (func->virtuality == DW_VIRTUALITY_virtual ||
	    func->virtuality == DW_VIRTUALITY_pure_virtual)
		printed += fprintf(fp, "virtual ");

	printed += ftype__fprintf(ftype, cu, function__name(func, cu),
				  inlined, 0, 0, false, conf, fp);

	if (func->virtuality == DW_VIRTUALITY_pure_virtual)
		printed += fprintf(fp, " = 0");

	return printed;
}

size_t function__fprintf_stats(const struct tag *tag, const struct cu *cu,
			       const struct conf_fprintf *conf, FILE *fp)
{
	struct function *func = tag__function(tag);
	size_t printed = lexblock__fprintf(&func->lexblock, cu, func, 0, conf, fp);

	printed += fprintf(fp, "/* size: %d", function__size(func));
	if (func->lexblock.nr_variables > 0)
		printed += fprintf(fp, ", variables: %u",
				   func->lexblock.nr_variables);
	if (func->lexblock.nr_labels > 0)
		printed += fprintf(fp, ", goto labels: %u",
				   func->lexblock.nr_labels);
	if (func->lexblock.nr_inline_expansions > 0)
		printed += fprintf(fp, ", inline expansions: %u (%d bytes)",
			func->lexblock.nr_inline_expansions,
			func->lexblock.size_inline_expansions);
	return printed + fprintf(fp, " */\n");
}

static size_t class__fprintf_cacheline_boundary(struct conf_fprintf *conf,
						uint32_t offset,
						FILE *fp)
{
	int indent = conf->indent;
	uint32_t cacheline = offset / cacheline_size;
	size_t printed = 0;

	if (cacheline > *conf->cachelinep) {
		const uint32_t cacheline_pos = offset % cacheline_size;
		const uint32_t cacheline_in_bytes = offset - cacheline_pos;

		if (cacheline_pos == 0)
			printed += fprintf(fp, "/* --- cacheline %u boundary "
					   "(%u bytes) --- */\n", cacheline,
					   cacheline_in_bytes);
		else
			printed += fprintf(fp, "/* --- cacheline %u boundary "
					   "(%u bytes) was %u bytes ago --- "
					   "*/\n", cacheline,
					   cacheline_in_bytes, cacheline_pos);

		printed += fprintf(fp, "%.*s", indent, tabs);

		*conf->cachelinep = cacheline;
	}
	return printed;
}

static size_t class__vtable_fprintf(struct class *class, const struct cu *cu,
				    const struct conf_fprintf *conf, FILE *fp)
{
	struct function *pos;
	size_t printed = 0;

	if (class->nr_vtable_entries == 0)
		goto out;

	printed += fprintf(fp, "%.*s/* vtable has %u entries: {\n",
			   conf->indent, tabs, class->nr_vtable_entries);

	list_for_each_entry(pos, &class->vtable, vtable_node) {
		printed += fprintf(fp, "%.*s   [%d] = %s(%s), \n",
				   conf->indent, tabs, pos->vtable_entry,
				   function__name(pos, cu),
				   function__linkage_name(pos, cu));
	}

	printed += fprintf(fp, "%.*s} */", conf->indent, tabs);
out:
	return printed;
}

static size_t __class__fprintf(struct class *class, const struct cu *cu,
			       const struct conf_fprintf *conf, FILE *fp)
{
	struct type *type = &class->type;
	size_t last_size = 0, size;
	uint8_t newline = 0;
	uint16_t nr_paddings = 0;
	uint16_t nr_forced_alignments = 0, nr_forced_alignment_holes = 0;
	uint32_t sum_forced_alignment_holes = 0;
	uint32_t sum_bytes = 0, sum_bits = 0;
	uint32_t sum_holes = 0;
	uint32_t sum_paddings = 0;
	uint32_t sum_bit_holes = 0;
	uint32_t cacheline = 0;
	int size_diff = 0;
	int first = 1;
	struct class_member *pos, *last = NULL;
	struct tag *tag_pos;
	const char *current_accessibility = NULL;
	struct conf_fprintf cconf = conf ? *conf : conf_fprintf__defaults;
	const uint16_t t = type->namespace.tag.tag;
	size_t printed = fprintf(fp, "%s%s%s%s%s",
				 cconf.prefix ?: "", cconf.prefix ? " " : "",
				 ((cconf.classes_as_structs ||
				   t == DW_TAG_structure_type) ? "struct" :
				  t == DW_TAG_class_type ? "class" :
							"interface"),
				 type__name(type, cu) ? " " : "",
				 type__name(type, cu) ?: "");
	int indent = cconf.indent;

	if (indent >= (int)sizeof(tabs))
		indent = sizeof(tabs) - 1;

	if (cconf.cachelinep == NULL)
		cconf.cachelinep = &cacheline;

	cconf.indent = indent + 1;
	cconf.no_semicolon = 0;

	class__infer_packed_attributes(class, cu);

	/* First look if we have DW_TAG_inheritance */
	type__for_each_tag(type, tag_pos) {
		const char *accessibility;

		if (tag_pos->tag != DW_TAG_inheritance)
			continue;

		if (first) {
			printed += fprintf(fp, " :");
			first = 0;
		} else
			printed += fprintf(fp, ",");

		pos = tag__class_member(tag_pos);

		if (pos->virtuality == DW_VIRTUALITY_virtual)
			printed += fprintf(fp, " virtual");

		accessibility = tag__accessibility(tag_pos);
		if (accessibility != NULL)
			printed += fprintf(fp, " %s", accessibility);

		struct tag *pos_type = cu__type(cu, tag_pos->type);
		if (pos_type != NULL)
			printed += fprintf(fp, " %s",
					   type__name(tag__type(pos_type), cu));
		else
			printed += tag__id_not_found_fprintf(fp, tag_pos->type);
	}

	printed += fprintf(fp, " {\n");

	if (class->pre_bit_hole > 0 && !cconf.suppress_comments) {
		if (!newline++) {
			fputc('\n', fp);
			++printed;
		}
		printed += fprintf(fp, "%.*s/* XXX %d bit%s hole, "
				   "try to pack */\n", cconf.indent, tabs,
				   class->pre_bit_hole,
				   class->pre_bit_hole != 1 ? "s" : "");
		sum_bit_holes += class->pre_bit_hole;
	}

	if (class->pre_hole > 0 && !cconf.suppress_comments) {
		if (!newline++) {
			fputc('\n', fp);
			++printed;
		}
		printed += fprintf(fp, "%.*s/* XXX %d byte%s hole, "
				   "try to pack */\n",
				   cconf.indent, tabs, class->pre_hole,
				   class->pre_hole != 1 ? "s" : "");
		sum_holes += class->pre_hole;
	}

	type__for_each_tag(type, tag_pos) {
		const char *accessibility = tag__accessibility(tag_pos);

		if (accessibility != NULL &&
		    accessibility != current_accessibility) {
			current_accessibility = accessibility;
			printed += fprintf(fp, "%.*s%s:\n\n",
					   cconf.indent - 1, tabs,
					   accessibility);
		}

		if (tag_pos->tag != DW_TAG_member &&
		    tag_pos->tag != DW_TAG_inheritance) {
			if (!cconf.show_only_data_members) {
				printed += tag__fprintf(tag_pos, cu, &cconf, fp);
				printed += fprintf(fp, "\n\n");
			}
			continue;
		}
		pos = tag__class_member(tag_pos);

		if (!cconf.suppress_aligned_attribute && pos->alignment != 0) {
			uint32_t forced_alignment_hole = last ? last->hole : class->pre_hole;

			if (forced_alignment_hole != 0) {
				++nr_forced_alignment_holes;
				sum_forced_alignment_holes += forced_alignment_hole;
			}
			++nr_forced_alignments;
		}
		/*
		 * These paranoid checks doesn't make much sense on
		 * DW_TAG_inheritance, have to understand why virtual public
		 * ancestors make the offset go backwards...
		 */
		if (last != NULL && tag_pos->tag == DW_TAG_member &&
		/*
		 * kmemcheck bitfield tricks use zero sized arrays as markers
		 * all over the place.
		 */
		    last_size != 0) {
			if (last->bit_hole != 0 && pos->bitfield_size) {
				uint8_t bitfield_size = last->bit_hole;
				struct tag *pos_type = cu__type(cu, pos->tag.type);

				if (pos_type == NULL) {
					printed += fprintf(fp, "%.*s", cconf.indent, tabs);
					printed += tag__id_not_found_fprintf(fp, pos->tag.type);
					continue;
				}
				/*
				 * Now check if this isn't something like 'unsigned :N' with N > 0,
				 * i.e. _explicitely_ adding a bit hole.
				 */
				if (last->byte_offset != pos->byte_offset) {
					printed += fprintf(fp, "\n%.*s/* Force alignment to the next boundary: */\n", cconf.indent, tabs);
					bitfield_size = 0;
				}

				printed += fprintf(fp, "%.*s", cconf.indent, tabs);
				printed += type__fprintf(pos_type, cu, "", &cconf, fp);
				printed += fprintf(fp, ":%u;\n", bitfield_size);
			}

			if (pos->byte_offset < last->byte_offset ||
			    (pos->byte_offset == last->byte_offset &&
			     last->bitfield_size == 0 &&
			     /*
			      * This is just when transitioning from a non-bitfield to
			      * a bitfield, think about zero sized arrays in the middle
			      * of a struct.
			      */
			     pos->bitfield_size != 0)) {
				if (!cconf.suppress_comments) {
					if (!newline++) {
						fputc('\n', fp);
						++printed;
					}
					printed += fprintf(fp, "%.*s/* Bitfield combined"
							   " with previous fields */\n",
							   cconf.indent, tabs);
				}
			} else {
				const ssize_t cc_last_size = ((ssize_t)pos->byte_offset -
							      (ssize_t)last->byte_offset);

				if (cc_last_size > 0 &&
				   (size_t)cc_last_size < last_size) {
					if (!cconf.suppress_comments) {
						if (!newline++) {
							fputc('\n', fp);
							++printed;
						}
						printed += fprintf(fp, "%.*s/* Bitfield combined"
								   " with next fields */\n",
								   cconf.indent, tabs);
					}
				}
			}
		}

		if (newline) {
			fputc('\n', fp);
			newline = 0;
			++printed;
		}

		struct tag *pos_type = cu__type(cu, pos->tag.type);
		if (pos_type == NULL) {
			printed += fprintf(fp, "%.*s", cconf.indent, tabs);
			printed += tag__id_not_found_fprintf(fp, pos->tag.type);
			continue;
		}

		cconf.last_member = list_is_last(&tag_pos->node, &type->namespace.tags);
		cconf.first_member = last == NULL;

		size = pos->byte_size;
		printed += fprintf(fp, "%.*s", cconf.indent, tabs);
		printed += struct_member__fprintf(pos, pos_type, cu, &cconf, fp);

		if (tag__is_struct(pos_type) && !cconf.suppress_comments) {
			struct class *tclass = tag__class(pos_type);
			uint16_t padding;
			/*
			 * We may not yet have looked for holes and paddings
			 * in this member's struct type.
			 */
			class__find_holes(tclass);
			class__infer_packed_attributes(tclass, cu);

			padding = tclass->padding;
			if (padding > 0) {
				++nr_paddings;
				sum_paddings += padding;
				if (!newline++) {
					fputc('\n', fp);
					++printed;
				}

				printed += fprintf(fp, "\n%.*s/* XXX last "
						   "struct has %d byte%s of "
						   "padding */", cconf.indent,
						   tabs, padding,
						   padding != 1 ? "s" : "");
			}
		}

		if (pos->bit_hole != 0 && !cconf.suppress_comments) {
			if (!newline++) {
				fputc('\n', fp);
				++printed;
			}
			printed += fprintf(fp, "\n%.*s/* XXX %d bit%s hole, "
					   "try to pack */", cconf.indent, tabs,
					   pos->bit_hole,
					   pos->bit_hole != 1 ? "s" : "");
			sum_bit_holes += pos->bit_hole;
		}

		if (pos->hole > 0 && !cconf.suppress_comments) {
			if (!newline++) {
				fputc('\n', fp);
				++printed;
			}
			printed += fprintf(fp, "\n%.*s/* XXX %d byte%s hole, "
					   "try to pack */",
					   cconf.indent, tabs, pos->hole,
					   pos->hole != 1 ? "s" : "");
			sum_holes += pos->hole;
		}

		fputc('\n', fp);
		++printed;

		/* XXX for now just skip these */
		if (tag_pos->tag == DW_TAG_inheritance)
			continue;
#if 0
		/*
 		 * This one was being skipped but caused problems with:
 		 * http://article.gmane.org/gmane.comp.debugging.dwarves/185
 		 * http://www.spinics.net/lists/dwarves/msg00119.html
 		 */
		if (pos->virtuality == DW_VIRTUALITY_virtual)
			continue;
#endif

		if (pos->bitfield_size) {
			sum_bits += pos->bitfield_size;
		} else {
			sum_bytes += pos->byte_size;
		}

		if (last == NULL || /* First member */
		    /*
		     * Last member was a zero sized array, typedef, struct, etc
		     */
		    last_size == 0 ||
		    /*
		     * We moved to a new offset
		     */
		    last->byte_offset != pos->byte_offset) {
			last_size = size;
		} else if (last->bitfield_size == 0 && pos->bitfield_size != 0) {
			/*
			 * Transitioned from from a non-bitfield to a
			 * bitfield sharing the same offset
			 */
			/*
			 * Compensate by removing the size of the
			 * last member that is "inside" this new
			 * member at the same offset.
			 *
			 * E.g.:
			 * struct foo {
			 * 	u8	a;   / 0    1 /
			 * 	int	b:1; / 0:23 4 /
			 * }
			 */
			last_size = size;
		}

		last = pos;
	}

	/*
	 * BTF doesn't have alignment info, for now use this infor from the loader
	 * to avoid adding the forced bitfield paddings and have btfdiff happy.
	 */
	if (class->padding != 0 && type->alignment == 0 && cconf.has_alignment_info &&
	    !cconf.suppress_force_paddings && last != NULL) {
		tag_pos = cu__type(cu, last->tag.type);
		size = tag__size(tag_pos, cu);

		if (is_power_of_2(size) && class->padding > cu->addr_size) {
			int added_padding;
			int bit_size = size * 8;

			printed += fprintf(fp, "\n%.*s/* Force padding: */\n", cconf.indent, tabs);

			for (added_padding = 0; added_padding < class->padding; added_padding += size) {
				printed += fprintf(fp, "%.*s", cconf.indent, tabs);
				printed += type__fprintf(tag_pos, cu, "", &cconf, fp);
				printed += fprintf(fp, ":%u;\n", bit_size);
			}
		}
	}

	if (!cconf.show_only_data_members)
		class__vtable_fprintf(class, cu, &cconf, fp);

	if (!cconf.emit_stats)
		goto out;

	printed += type__fprintf_stats(type, cu, &cconf, fp);

	if (sum_holes > 0 || sum_bit_holes > 0) {
		if (sum_bytes > 0) {
			printed += fprintf(fp, "%.*s/* sum members: %u",
					   cconf.indent, tabs, sum_bytes);
			if (sum_holes > 0)
				printed += fprintf(fp, ", holes: %d, sum holes: %u",
						   class->nr_holes, sum_holes);
			printed += fprintf(fp, " */\n");
		}
		if (sum_bits > 0) {
			printed += fprintf(fp, "%.*s/* sum bitfield members: %u bits",
					   cconf.indent, tabs, sum_bits);
			if (sum_bit_holes > 0)
				printed += fprintf(fp, ", bit holes: %d, sum bit holes: %u bits",
						   class->nr_bit_holes, sum_bit_holes);
			else
				printed += fprintf(fp, " (%u bytes)", sum_bits / 8);
			printed += fprintf(fp, " */\n");
		}
	}
	if (class->padding > 0)
		printed += fprintf(fp, "%.*s/* padding: %u */\n",
				   cconf.indent,
				   tabs, class->padding);
	if (nr_paddings > 0)
		printed += fprintf(fp, "%.*s/* paddings: %u, sum paddings: "
				   "%u */\n",
				   cconf.indent, tabs,
				   nr_paddings, sum_paddings);
	if (class->bit_padding > 0)
		printed += fprintf(fp, "%.*s/* bit_padding: %u bits */\n",
				   cconf.indent, tabs,
				   class->bit_padding);
	if (!cconf.suppress_aligned_attribute && nr_forced_alignments != 0) {
		printed += fprintf(fp, "%.*s/* forced alignments: %u",
				   cconf.indent, tabs,
				   nr_forced_alignments);
		if (nr_forced_alignment_holes != 0) {
			printed += fprintf(fp, ", forced holes: %u, sum forced holes: %u",
					   nr_forced_alignment_holes,
					   sum_forced_alignment_holes);
		}
		printed += fprintf(fp, " */\n");
	}
	cacheline = (cconf.base_offset + type->size) % cacheline_size;
	if (cacheline != 0)
		printed += fprintf(fp, "%.*s/* last cacheline: %u bytes */\n",
				   cconf.indent, tabs,
				   cacheline);
	if (cconf.show_first_biggest_size_base_type_member &&
	    type->nr_members != 0) {
		struct class_member *m = type__find_first_biggest_size_base_type_member(type, cu);

		printed += fprintf(fp, "%.*s/* first biggest size base type member: %s %u %zd */\n",
				   cconf.indent, tabs,
				   class_member__name(m, cu), m->byte_offset,
				   m->byte_size);
	}

	size_diff = type->size * 8 - (sum_bytes * 8 + sum_bits + sum_holes * 8 + sum_bit_holes +
				      class->padding * 8 + class->bit_padding);
	if (size_diff && type->nr_members != 0)
		printed += fprintf(fp, "\n%.*s/* BRAIN FART ALERT! %d bytes != "
				   "%u (member bytes) + %u (member bits) "
				   "+ %u (byte holes) + %u (bit holes), diff = %d bits */\n",
				   cconf.indent, tabs,
				   type->size, sum_bytes, sum_bits, sum_holes, sum_bit_holes, size_diff);
out:
	printed += fprintf(fp, "%.*s}", indent, tabs);

	if (class->is_packed && !cconf.suppress_packed)
		printed += fprintf(fp, " __attribute__((__packed__))");

	if (cconf.suffix)
		printed += fprintf(fp, " %s", cconf.suffix);

	/*
	 * A class that was marked packed by class__infer_packed_attributes
	 * because it has an alignment that is different than its natural
	 * alignment, should not print the __alignment__ here, just the
	 * __packed__ attribute.
	 */
	if (!cconf.suppress_aligned_attribute && type->alignment != 0 && !class->is_packed)
		printed += fprintf(fp, " __attribute__((__aligned__(%u)))", type->alignment);

	return printed;
}

size_t class__fprintf(struct class *class, const struct cu *cu, FILE *fp)
{
	return __class__fprintf(class, cu, NULL, fp);
}

static size_t variable__fprintf(const struct tag *tag, const struct cu *cu,
				const struct conf_fprintf *conf, FILE *fp)
{
	const struct dw_variable *var = tag__variable(tag);
	const char *name = variable__name(var, cu);
	size_t printed = 0;

	if (name != NULL) {
		struct tag *type = cu__type(cu, var->ip.tag.type);
		if (type != NULL) {
			const char *varprefix = variable__prefix(var);

			if (varprefix != NULL)
				printed += fprintf(fp, "%s", varprefix);
			printed += type__fprintf(type, cu, name, conf, fp);
		}
	}
	return printed;
}

static size_t namespace__fprintf(const struct tag *tag, const struct cu *cu,
				 const struct conf_fprintf *conf, FILE *fp)
{
	struct namespace *space = tag__namespace(tag);
	struct conf_fprintf cconf = *conf;
	size_t printed = fprintf(fp, "namespace %s {\n",
				 namespace__name(space, cu));
	struct tag *pos;

	++cconf.indent;
	cconf.no_semicolon = 0;

	namespace__for_each_tag(space, pos) {
		printed += tag__fprintf(pos, cu, &cconf, fp);
		printed += fprintf(fp, "\n\n");
	}

	return printed + fprintf(fp, "}");
}

size_t tag__fprintf(struct tag *tag, const struct cu *cu,
		    const struct conf_fprintf *conf, FILE *fp)
{
	size_t printed = 0;
	struct conf_fprintf tconf;
	const struct conf_fprintf *pconf = conf;

	if (conf == NULL) {
		tconf = conf_fprintf__defaults;
		pconf = &tconf;

		if (tconf.expand_types)
			tconf.name_spacing = 55;
		else if (tag__is_union(tag))
			tconf.name_spacing = 21;
	} else if (conf->name_spacing == 0 || conf->type_spacing == 0) {
		tconf = *conf;
		pconf = &tconf;

		if (tconf.name_spacing == 0) {
			if (tconf.expand_types)
				tconf.name_spacing = 55;
			else
				tconf.name_spacing = tag__is_union(tag) ? 21 : 23;
		}
		if (tconf.type_spacing == 0)
			tconf.type_spacing = 26;
	}

	if (pconf->expand_types)
		++tag->recursivity_level;

	if (pconf->show_decl_info) {
		printed += fprintf(fp, "%.*s", pconf->indent, tabs);
		printed += fprintf(fp, "/* Used at: %s */\n", cu->name);
		printed += fprintf(fp, "%.*s", pconf->indent, tabs);
		printed += tag__fprintf_decl_info(tag, cu, fp);
	}
	printed += fprintf(fp, "%.*s", pconf->indent, tabs);

	switch (tag->tag) {
	case DW_TAG_array_type:
		printed += array_type__fprintf(tag, cu, "array", pconf, fp);
		break;
	case DW_TAG_enumeration_type:
		printed += enumeration__fprintf(tag, cu, pconf, fp);
		break;
	case DW_TAG_typedef:
		printed += typedef__fprintf(tag, cu, pconf, fp);
		break;
	case DW_TAG_class_type:
	case DW_TAG_interface_type:
	case DW_TAG_structure_type:
		printed += __class__fprintf(tag__class(tag), cu, pconf, fp);
		break;
	case DW_TAG_subroutine_type:
		printed += ftype__fprintf(tag__ftype(tag), cu, NULL, false, false, 0, true, pconf, fp);
		break;
	case DW_TAG_namespace:
		printed += namespace__fprintf(tag, cu, pconf, fp);
		break;
	case DW_TAG_subprogram:
		printed += function__fprintf(tag, cu, pconf, fp);
		break;
	case DW_TAG_union_type:
		printed += union__fprintf(tag__type(tag), cu, pconf, fp);
		break;
	case DW_TAG_variable:
		printed += variable__fprintf(tag, cu, pconf, fp);
		break;
	case DW_TAG_imported_declaration:
		printed += imported_declaration__fprintf(tag, cu, fp);
		break;
	case DW_TAG_imported_module:
		printed += imported_module__fprintf(tag, cu, fp);
		break;
	default:
		printed += fprintf(fp, "/* %s: %s tag not supported! */",
				   __func__, dwarf_tag_name(tag->tag));
		break;
	}

	if (!pconf->no_semicolon) {
		fputc(';', fp);
		++printed;
	}

	if (tag__is_function(tag) && !pconf->suppress_comments) {
		const struct function *func = tag__function(tag);

		if (func->linkage_name)
			printed += fprintf(fp, " /* linkage=%s */",
					   function__linkage_name(func, cu));
	}

	if (pconf->expand_types)
		--tag->recursivity_level;

	return printed;
}

void cus__print_error_msg(const char *progname, const struct cus *cus,
			  const char *filename, const int err)
{
	if (err == -EINVAL || (cus != NULL && list_empty(&cus->cus)))
		fprintf(stderr, "%s: couldn't load debugging info from %s\n",
		       progname, filename);
	else
		fprintf(stderr, "%s: %s\n", progname, strerror(err));
}

void dwarves__fprintf_init(uint16_t user_cacheline_size)
{
	if (user_cacheline_size == 0) {
#ifdef _SC_LEVEL1_DCACHE_LINESIZE
		long sys_cacheline_size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
#else
		long sys_cacheline_size = 0;
#endif
		if (sys_cacheline_size > 0)
			cacheline_size = sys_cacheline_size;
		else
			cacheline_size = 64; /* Fall back to a sane value */
	} else
		cacheline_size = user_cacheline_size;
}
