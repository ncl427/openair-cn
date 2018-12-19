/*
 * Generated by asn1c-0.9.24 (http://lionet.info/asn1c)
 * From ASN.1 module "S1AP-IEs"
 * 	found in "/root/openair-cn/SRC/S1AP/MESSAGES/ASN1/R10.5/S1AP-IEs.asn"
 * 	`asn1c -gen-PER`
 */

#ifndef	_S1ap_ReceiveStatusofULPDCPSDUs_H_
#define	_S1ap_ReceiveStatusofULPDCPSDUs_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* S1ap-ReceiveStatusofULPDCPSDUs */
typedef BIT_STRING_t	 S1ap_ReceiveStatusofULPDCPSDUs_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_S1ap_ReceiveStatusofULPDCPSDUs;
asn_struct_free_f S1ap_ReceiveStatusofULPDCPSDUs_free;
asn_struct_print_f S1ap_ReceiveStatusofULPDCPSDUs_print;
asn_constr_check_f S1ap_ReceiveStatusofULPDCPSDUs_constraint;
ber_type_decoder_f S1ap_ReceiveStatusofULPDCPSDUs_decode_ber;
der_type_encoder_f S1ap_ReceiveStatusofULPDCPSDUs_encode_der;
xer_type_decoder_f S1ap_ReceiveStatusofULPDCPSDUs_decode_xer;
xer_type_encoder_f S1ap_ReceiveStatusofULPDCPSDUs_encode_xer;
per_type_decoder_f S1ap_ReceiveStatusofULPDCPSDUs_decode_uper;
per_type_encoder_f S1ap_ReceiveStatusofULPDCPSDUs_encode_uper;
per_type_decoder_f S1ap_ReceiveStatusofULPDCPSDUs_decode_aper;
per_type_encoder_f S1ap_ReceiveStatusofULPDCPSDUs_encode_aper;
type_compare_f     S1ap_ReceiveStatusofULPDCPSDUs_compare;

#ifdef __cplusplus
}
#endif

#endif	/* _S1ap_ReceiveStatusofULPDCPSDUs_H_ */
#include <asn_internal.h>
