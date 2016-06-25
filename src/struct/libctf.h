#ifndef _LIBCTF_H
#define _LIBCTF_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <elf.h>

#include "gobuffer.h"
#include "elf_symtab.h"

struct ctf {
	void		  *buf;
	void		  *priv;
	Elf		  *elf;
	struct elf_symtab *symtab;
	GElf_Ehdr	  ehdr;
	struct gobuffer	  objects; /* data/variables */
	struct gobuffer	  types;
	struct gobuffer	  funcs;
	struct gobuffer   *strings;
	char		  *filename;
	size_t		  size;
	int		  swapped;
	int		  in_fd;
	uint8_t		  wordsize;
	unsigned int	  type_index;
};

struct ctf *ctf__new(const char *filename, Elf *elf);
void ctf__delete(struct ctf *ctf);

bool ctf__ignore_symtab_function(const GElf_Sym *sym, const char *sym_name);
bool ctf__ignore_symtab_object(const GElf_Sym *sym, const char *sym_name);

int ctf__load(struct ctf *ctf);

uint16_t ctf__get16(struct ctf *ctf, uint16_t *p);
uint32_t ctf__get32(struct ctf *ctf, uint32_t *p);
void ctf__put16(struct ctf *ctf, uint16_t *p, uint16_t val);
void ctf__put32(struct ctf *ctf, uint32_t *p, uint32_t val);

void *ctf__get_buffer(struct ctf *ctf);
size_t ctf__get_size(struct ctf *ctf);

int ctf__load_symtab(struct ctf *ctf);

int ctf__add_base_type(struct ctf *ctf, uint32_t name, uint16_t size);
int ctf__add_fwd_decl(struct ctf *ctf, uint32_t name);
int ctf__add_short_type(struct ctf *ctf, uint16_t kind, uint16_t type,
			uint32_t name);
void ctf__add_short_member(struct ctf *ctf, uint32_t name, uint16_t type,
			   uint16_t offset, int64_t *position);
void ctf__add_full_member(struct ctf *ctf, uint32_t name, uint16_t type,
			  uint64_t offset, int64_t *position);
int ctf__add_struct(struct ctf *ctf, uint16_t kind, uint32_t name,
		    uint64_t size, uint16_t nr_members, int64_t *position);
int ctf__add_array(struct ctf *ctf, uint16_t type, uint16_t index_type,
		   uint32_t nelems);
void ctf__add_parameter(struct ctf *ctf, uint16_t type, int64_t *position);
int ctf__add_function_type(struct ctf *ctf, uint16_t type,
			   uint16_t nr_parms, bool varargs, int64_t *position);
int ctf__add_enumeration_type(struct ctf *ctf, uint32_t name, uint16_t size,
			      uint16_t nr_entries, int64_t *position);
void ctf__add_enumerator(struct ctf *ctf, uint32_t name, uint32_t value,
			 int64_t *position);

void ctf__add_function_parameter(struct ctf *ctf, uint16_t type,
				 int64_t *position);
int ctf__add_function(struct ctf *ctf, uint16_t type, uint16_t nr_parms,
		      bool varargs, int64_t *position);

int ctf__add_object(struct ctf *ctf, uint16_t type);

void ctf__set_strings(struct ctf *ctf, struct gobuffer *strings);
int  ctf__encode(struct ctf *ctf, uint8_t flags);

char *ctf__string(struct ctf *ctf, uint32_t ref);

/**
 * ctf__for_each_symtab_function - iterate thru all the symtab functions
 *
 * @ctf: struct ctf instance to iterate
 * @index: uint32_t index
 * @sym: GElf_Sym iterator
 */
#define ctf__for_each_symtab_function(ctf, index, sym)			      \
	elf_symtab__for_each_symbol(ctf->symtab, index, sym)		      \
		if (ctf__ignore_symtab_function(&sym,			      \
						elf_sym__name(&sym,	      \
							      ctf->symtab)))  \
			continue;					      \
		else

/**
 * ctf__for_each_symtab_object - iterate thru all the symtab objects
 *
 * @ctf: struct ctf instance to iterate
 * @index: uint32_t index
 * @sym: GElf_Sym iterator
 */
#define ctf__for_each_symtab_object(ctf, index, sym)			      \
	elf_symtab__for_each_symbol(ctf->symtab, index, sym)		      \
		if (ctf__ignore_symtab_object(&sym,			      \
					      elf_sym__name(&sym,	      \
							    ctf->symtab)))    \
			continue;					      \
		else


#endif /* _LIBCTF_H */
