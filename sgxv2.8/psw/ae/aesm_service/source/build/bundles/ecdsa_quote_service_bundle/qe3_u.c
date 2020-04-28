#include "qe3_u.h"
#include <errno.h>

typedef struct ms_get_pce_encrypt_key_t {
	uint32_t ms_retval;
	const sgx_target_info_t* ms_pce_target_info;
	sgx_report_t* ms_p_qe_report;
	uint8_t ms_crypto_suite;
	uint16_t ms_cert_key_type;
	uint32_t ms_key_size;
	uint8_t* ms_p_public_key;
} ms_get_pce_encrypt_key_t;

typedef struct ms_gen_att_key_t {
	uint32_t ms_retval;
	uint8_t* ms_p_blob;
	uint32_t ms_blob_size;
	const sgx_target_info_t* ms_p_pce_target_info;
	sgx_report_t* ms_qe_report;
	uint8_t* ms_p_authentication_data;
	uint32_t ms_authentication_data_size;
} ms_gen_att_key_t;

typedef struct ms_verify_blob_t {
	uint32_t ms_retval;
	uint8_t* ms_p_blob;
	uint32_t ms_blob_size;
	uint8_t* ms_p_is_resealed;
	sgx_report_body_t* ms_p_report;
	uint32_t ms_pub_key_id_size;
	uint8_t* ms_p_pub_key_id;
} ms_verify_blob_t;

typedef struct ms_store_cert_data_t {
	uint32_t ms_retval;
	ref_plaintext_ecdsa_data_sdk_t* ms_p_plaintext_data;
	sgx_ql_cert_key_type_t ms_certification_key_type;
	uint8_t* ms_p_encrypted_ppid;
	uint32_t ms_encrypted_ppid_size;
	uint8_t* ms_p_blob;
	uint32_t ms_blob_size;
} ms_store_cert_data_t;

typedef struct ms_gen_quote_t {
	uint32_t ms_retval;
	uint8_t* ms_p_blob;
	uint32_t ms_blob_size;
	const sgx_report_t* ms_p_app_report;
	const sgx_quote_nonce_t* ms_p_nonce;
	const sgx_target_info_t* ms_p_app_enclave_target_info;
	sgx_report_t* ms_p_qe_report;
	uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
	sgx_isv_svn_t ms_pce_isvnsvn;
	const uint8_t* ms_p_cert_data;
	uint32_t ms_cert_data_size;
} ms_gen_quote_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_qe3 = {
	0,
	{ NULL },
};
sgx_status_t get_pce_encrypt_key(sgx_enclave_id_t eid, uint32_t* retval, const sgx_target_info_t* pce_target_info, sgx_report_t* p_qe_report, uint8_t crypto_suite, uint16_t cert_key_type, uint32_t key_size, uint8_t* p_public_key)
{
	sgx_status_t status;
	ms_get_pce_encrypt_key_t ms;
	ms.ms_pce_target_info = pce_target_info;
	ms.ms_p_qe_report = p_qe_report;
	ms.ms_crypto_suite = crypto_suite;
	ms.ms_cert_key_type = cert_key_type;
	ms.ms_key_size = key_size;
	ms.ms_p_public_key = p_public_key;
	status = sgx_ecall(eid, 0, &ocall_table_qe3, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t gen_att_key(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* p_blob, uint32_t blob_size, const sgx_target_info_t* p_pce_target_info, sgx_report_t* qe_report, uint8_t* p_authentication_data, uint32_t authentication_data_size)
{
	sgx_status_t status;
	ms_gen_att_key_t ms;
	ms.ms_p_blob = p_blob;
	ms.ms_blob_size = blob_size;
	ms.ms_p_pce_target_info = p_pce_target_info;
	ms.ms_qe_report = qe_report;
	ms.ms_p_authentication_data = p_authentication_data;
	ms.ms_authentication_data_size = authentication_data_size;
	status = sgx_ecall(eid, 1, &ocall_table_qe3, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t verify_blob(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* p_blob, uint32_t blob_size, uint8_t* p_is_resealed, sgx_report_body_t* p_report, uint32_t pub_key_id_size, uint8_t* p_pub_key_id)
{
	sgx_status_t status;
	ms_verify_blob_t ms;
	ms.ms_p_blob = p_blob;
	ms.ms_blob_size = blob_size;
	ms.ms_p_is_resealed = p_is_resealed;
	ms.ms_p_report = p_report;
	ms.ms_pub_key_id_size = pub_key_id_size;
	ms.ms_p_pub_key_id = p_pub_key_id;
	status = sgx_ecall(eid, 2, &ocall_table_qe3, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t store_cert_data(sgx_enclave_id_t eid, uint32_t* retval, ref_plaintext_ecdsa_data_sdk_t* p_plaintext_data, sgx_ql_cert_key_type_t certification_key_type, uint8_t* p_encrypted_ppid, uint32_t encrypted_ppid_size, uint8_t* p_blob, uint32_t blob_size)
{
	sgx_status_t status;
	ms_store_cert_data_t ms;
	ms.ms_p_plaintext_data = p_plaintext_data;
	ms.ms_certification_key_type = certification_key_type;
	ms.ms_p_encrypted_ppid = p_encrypted_ppid;
	ms.ms_encrypted_ppid_size = encrypted_ppid_size;
	ms.ms_p_blob = p_blob;
	ms.ms_blob_size = blob_size;
	status = sgx_ecall(eid, 3, &ocall_table_qe3, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t gen_quote(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* p_blob, uint32_t blob_size, const sgx_report_t* p_app_report, const sgx_quote_nonce_t* p_nonce, const sgx_target_info_t* p_app_enclave_target_info, sgx_report_t* p_qe_report, uint8_t* p_quote, uint32_t quote_size, sgx_isv_svn_t pce_isvnsvn, const uint8_t* p_cert_data, uint32_t cert_data_size)
{
	sgx_status_t status;
	ms_gen_quote_t ms;
	ms.ms_p_blob = p_blob;
	ms.ms_blob_size = blob_size;
	ms.ms_p_app_report = p_app_report;
	ms.ms_p_nonce = p_nonce;
	ms.ms_p_app_enclave_target_info = p_app_enclave_target_info;
	ms.ms_p_qe_report = p_qe_report;
	ms.ms_p_quote = p_quote;
	ms.ms_quote_size = quote_size;
	ms.ms_pce_isvnsvn = pce_isvnsvn;
	ms.ms_p_cert_data = p_cert_data;
	ms.ms_cert_data_size = cert_data_size;
	status = sgx_ecall(eid, 4, &ocall_table_qe3, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

