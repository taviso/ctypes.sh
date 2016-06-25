#ifndef _CTF_H
#define _CTF_H

#include <stdint.h>

struct ctf_header {
	uint16_t	ctf_magic;	/* Header magic value            */
#define CTF_MAGIC	0xcff1
#define CTF_MAGIC_SWAP	0xf1cf

	uint8_t		ctf_version;	/* Header version                */
#define CTF_VERSION	2

	uint8_t		ctf_flags;	/* Header flags                  */
#define CTF_FLAGS_COMPR	0x01

	uint32_t	ctf_parent_label; /* Label of parent CTF object  */
	uint32_t	ctf_parent_name;  /* Name of parent CTF object   */

	/* All offsets are in bytes are relative to the end of
	 * this header.
	 */
	uint32_t	ctf_label_off;	/* Offset of label section       */
	uint32_t	ctf_object_off;	/* Offset of data object section */
	uint32_t	ctf_func_off;	/* Offset of function section    */
	uint32_t	ctf_type_off;	/* Offset of type section        */
	uint32_t	ctf_str_off;	/* Offset of string section      */
	uint32_t	ctf_str_len;	/* Length of string section      */
};

#define CTF_REF_OFFSET(REF)	((REF) & 0x7fffffff)
#define CTF_REF_TBL_ID(REF)	(((REF) >> 31) & 0x1)
#define CTF_STR_TBL_ID_0	0
#define CTF_STR_TBL_ID_1	1

#define CTF_REF_ENCODE(TBL, OFF) (((TBL) << 31) | (OFF))

struct ctf_label_ent {
	uint32_t	ctf_label_ref;
	uint32_t	ctf_type_index;
};

/* Types are encoded with ctf_short_type so long as the ctf_size
 * field can be fully represented in a uint16_t.  If not, then
 * the ctf_size is given the value 0xffff and ctf_full_type is
 * used.
 */
struct ctf_short_type {
	uint32_t		ctf_name;
	uint16_t		ctf_info;
	union {
		uint16_t	ctf_size;
		uint16_t	ctf_type;
	};
};

struct ctf_full_type {
	struct ctf_short_type	base;
	uint32_t		ctf_size_high;
	uint32_t		ctf_size_low;
};

#define CTF_GET_KIND(VAL)	(((VAL) >> 11) & 0x1f)
#define CTF_GET_VLEN(VAL)	((VAL) & 0x3ff)
#define CTF_ISROOT(VAL)		(((VAL) & 0x400) != 0)

#define CTF_INFO_ENCODE(KIND, VLEN, ISROOT) \
	(((ISROOT) ? 0x400 : 0) | ((KIND) << 11) | (VLEN))

#define CTF_TYPE_KIND_UNKN	0	/* Unknown	*/
#define CTF_TYPE_KIND_INT	1	/* Integer	*/
#define CTF_TYPE_KIND_FLT	2	/* Float	*/
#define CTF_TYPE_KIND_PTR	3	/* Pointer	*/
#define CTF_TYPE_KIND_ARR	4	/* Array	*/
#define CTF_TYPE_KIND_FUNC	5	/* Function	*/
#define CTF_TYPE_KIND_STR	6	/* Struct	*/
#define CTF_TYPE_KIND_UNION	7	/* Union	*/
#define CTF_TYPE_KIND_ENUM	8	/* Enumeration	*/
#define CTF_TYPE_KIND_FWD	9	/* Forward	*/
#define CTF_TYPE_KIND_TYPDEF	10	/* Typedef	*/
#define CTF_TYPE_KIND_VOLATILE	11	/* Volatile	*/
#define CTF_TYPE_KIND_CONST	12	/* Const	*/
#define CTF_TYPE_KIND_RESTRICT	13	/* Restrict	*/
#define CTF_TYPE_KIND_MAX	31

#define CTF_TYPE_INT_ATTRS(VAL)		((VAL) >> 24)
#define CTF_TYPE_INT_OFFSET(VAL)	(((VAL) >> 16) & 0xff)
#define CTF_TYPE_INT_BITS(VAL)		((VAL) & 0xffff)

#define CTF_TYPE_INT_ENCODE(ATTRS, OFF, BITS) \
	(((ATTRS) << 24) | ((OFF) << 16) | (BITS))

/* Integer type attributes */
#define CTF_TYPE_INT_SIGNED	0x1
#define CTF_TYPE_INT_CHAR	0x2
#define CTF_TYPE_INT_BOOL	0x4
#define CTF_TYPE_INT_VARARGS	0x8

#define CTF_TYPE_FP_ATTRS(VAL)		((VAL) >> 24)
#define CTF_TYPE_FP_OFFSET(VAL)		(((VAL) >> 16) & 0xff)
#define CTF_TYPE_FP_BITS(VAL)		((VAL) & 0xffff)

#define CTF_TYPE_FP_ENCODE(ATTRS, OFF, BITS) \
	(((ATTRS) << 24) | ((OFF) << 16) | (BITS))

/* Possible values for the float type attribute field */
#define CTF_TYPE_FP_SINGLE	1
#define CTF_TYPE_FP_DOUBLE	2
#define CTF_TYPE_FP_CMPLX	3
#define CTF_TYPE_FP_CMPLX_DBL	4
#define CTF_TYPE_FP_CMPLX_LDBL	5
#define CTF_TYPE_FP_LDBL	6
#define CTF_TYPE_FP_INTVL	7
#define CTF_TYPE_FP_INTVL_DBL	8
#define CTF_TYPE_FP_INTVL_LDBL	9
#define CTF_TYPE_FP_IMGRY	10
#define CTF_TYPE_FP_IMGRY_DBL	11
#define CTF_TYPE_FP_IMGRY_LDBL	12
#define CTF_TYPE_FP_MAX		12

struct ctf_enum {
	uint32_t	ctf_enum_name;
	uint32_t	ctf_enum_val;
};

struct ctf_array {
	uint16_t	ctf_array_type;
	uint16_t	ctf_array_index_type;
	uint32_t	ctf_array_nelems;
};

/* Struct members are encoded with either ctf_short_member or
 * ctf_full_member, depending upon the 'size' of the struct or
 * union being defined.  If it is less than CTF_SHORT_MEMBER_LIMIT
 * then ctf_short_member objects are used to encode, else
 * ctf_full_member is used.
 */
#define CTF_SHORT_MEMBER_LIMIT	8192

struct ctf_short_member {
	uint32_t	ctf_member_name;
	uint16_t	ctf_member_type;
	uint16_t	ctf_member_offset;
};

struct ctf_full_member {
	uint32_t	ctf_member_name;
	uint16_t	ctf_member_type;
	uint16_t	ctf_member_unused;
	uint32_t	ctf_member_offset_high;
	uint32_t	ctf_member_offset_low;
};

#endif /* _CTF_H */
