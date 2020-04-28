#ifndef QE3_U_H__
#define QE3_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_report.h"
#include "sgx_quote.h"
#include "sgx_quote_3.h"
#include "user_types.h"
#include "ecdsa_quote.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t get_pce_encrypt_key(sgx_enclave_id_t eid, uint32_t* retval, const sgx_target_info_t* pce_target_info, sgx_report_t* p_qe_report, uint8_t crypto_suite, uint16_t cert_key_type, uint32_t key_size, uint8_t* p_public_key);
sgx_status_t gen_att_key(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* p_blob, uint32_t blob_size, const sgx_target_info_t* p_pce_target_info, sgx_report_t* qe_report, uint8_t* p_authentication_data, uint32_t authentication_data_size);
sgx_status_t verify_blob(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* p_blob, uint32_t blob_size, uint8_t* p_is_resealed, sgx_report_body_t* p_report, uint32_t pub_key_id_size, uint8_t* p_pub_key_id);
sgx_status_t store_cert_data(sgx_enclave_id_t eid, uint32_t* retval, ref_plaintext_ecdsa_data_sdk_t* p_plaintext_data, sgx_ql_cert_key_type_t certification_key_type, uint8_t* p_encrypted_ppid, uint32_t encrypted_ppid_size, uint8_t* p_blob, uint32_t blob_size);
sgx_status_t gen_quote(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* p_blob, uint32_t blob_size, const sgx_report_t* p_app_report, const sgx_quote_nonce_t* p_nonce, const sgx_target_info_t* p_app_enclave_target_info, sgx_report_t* p_qe_report, uint8_t* p_quote, uint32_t quote_size, sgx_isv_svn_t pce_isvnsvn, const uint8_t* p_cert_data, uint32_t cert_data_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
