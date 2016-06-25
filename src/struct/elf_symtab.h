#ifndef _ELF_SYMTAB_H_
#define _ELF_SYMTAB_H_ 1
/*
  Copyright (C) 2009 Red Hat Inc.
  Copyright (C) 2009 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <stdbool.h>
#include <stdint.h>
#include <gelf.h>
#include <elf.h>

struct elf_symtab {
	uint32_t  nr_syms;
	Elf_Data  *syms;
	Elf_Data  *symstrs;
	char	  *name;
};

struct elf_symtab *elf_symtab__new(const char *name, Elf *elf, GElf_Ehdr *ehdr);
void elf_symtab__delete(struct elf_symtab *symtab);

static inline uint32_t elf_symtab__nr_symbols(const struct elf_symtab *symtab)
{
	return symtab->nr_syms;
}

static inline const char *elf_sym__name(const GElf_Sym *sym,
					const struct elf_symtab *symtab)
{
	return symtab->symstrs->d_buf + sym->st_name;
}

static inline uint8_t elf_sym__type(const GElf_Sym *sym)
{
	return GELF_ST_TYPE(sym->st_info);
}

static inline uint16_t elf_sym__section(const GElf_Sym *sym)
{
	return sym->st_shndx;
}

static inline uint8_t elf_sym__bind(const GElf_Sym *sym)
{
	return GELF_ST_BIND(sym->st_info);
}

static inline uint8_t elf_sym__visibility(const GElf_Sym *sym)
{
	return GELF_ST_VISIBILITY(sym->st_other);
}

static inline uint32_t elf_sym__size(const GElf_Sym *sym)
{
	return sym->st_size;
}

static inline uint64_t elf_sym__value(const GElf_Sym *sym)
{
	return sym->st_value;
}

static inline bool elf_sym__is_local_function(const GElf_Sym *sym)
{
	return elf_sym__type(sym) == STT_FUNC &&
	       sym->st_name != 0 &&
	       sym->st_shndx != SHN_UNDEF;
}

static inline bool elf_sym__is_local_object(const GElf_Sym *sym)
{
	return elf_sym__type(sym) == STT_OBJECT &&
	       sym->st_name != 0 &&
	       sym->st_shndx != SHN_UNDEF;
}

/**
 * elf_symtab__for_each_symbol - iterate thru all the symbols
 *
 * @symtab: struct elf_symtab instance to iterate
 * @index: uint32_t index
 * @sym: GElf_Sym iterator
 */
#define elf_symtab__for_each_symbol(symtab, index, sym) \
	for (index = 0, gelf_getsym(symtab->syms, index, &sym);\
	     index < symtab->nr_syms; \
	     index++, gelf_getsym(symtab->syms, index, &sym))

#endif /* _ELF_SYMTAB_H_ */
