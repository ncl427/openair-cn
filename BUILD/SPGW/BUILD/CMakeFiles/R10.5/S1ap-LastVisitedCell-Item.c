/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "/root/openair-cn/SRC/S1AP/MESSAGES/ASN1/R10.5/S1AP-IEs.asn"
 * 	`asn1c -gen-PER`
 */

#include "S1ap-LastVisitedCell-Item.h"

static asn_per_constraints_t asn_PER_type_S1ap_LastVisitedCell_Item_constr_1 GCC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  2,  2,  0,  2 }	/* (0..2,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_S1ap_LastVisitedCell_Item_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct S1ap_LastVisitedCell_Item, choice.e_UTRAN_Cell),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1ap_LastVisitedEUTRANCellInformation,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"e-UTRAN-Cell"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct S1ap_LastVisitedCell_Item, choice.uTRAN_Cell),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_S1ap_LastVisitedUTRANCellInformation,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"uTRAN-Cell"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct S1ap_LastVisitedCell_Item, choice.gERAN_Cell),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_S1ap_LastVisitedGERANCellInformation,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"gERAN-Cell"
		},
};
static asn_TYPE_tag2member_t asn_MAP_S1ap_LastVisitedCell_Item_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* e-UTRAN-Cell at 783 */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* uTRAN-Cell at 784 */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* gERAN-Cell at 785 */
};
static asn_CHOICE_specifics_t asn_SPC_S1ap_LastVisitedCell_Item_specs_1 = {
	sizeof(struct S1ap_LastVisitedCell_Item),
	offsetof(struct S1ap_LastVisitedCell_Item, _asn_ctx),
	offsetof(struct S1ap_LastVisitedCell_Item, present),
	sizeof(((struct S1ap_LastVisitedCell_Item *)0)->present),
	asn_MAP_S1ap_LastVisitedCell_Item_tag2el_1,
	3,	/* Count of tags in the map */
	0,
	3	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_S1ap_LastVisitedCell_Item = {
	"S1ap-LastVisitedCell-Item",
	"S1ap-LastVisitedCell-Item",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_decode_aper,
	CHOICE_encode_aper,
	CHOICE_compare,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_S1ap_LastVisitedCell_Item_constr_1,
	asn_MBR_S1ap_LastVisitedCell_Item_1,
	3,	/* Elements count */
	&asn_SPC_S1ap_LastVisitedCell_Item_specs_1	/* Additional specs */
};

