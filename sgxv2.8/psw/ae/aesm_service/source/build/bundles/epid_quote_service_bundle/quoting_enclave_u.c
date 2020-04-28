#include "quoting_enclave_u.h"
#include <errno.h>

typedef struct ms_verify_blob_t {
	uint32_t ms_retval;
	uint8_t* ms_p_blob;
	uint32_t ms_blob_size;
	uint8_t* ms_p_is_resealed;
	sgx_cpu_svn_t* ms_p_cpusvn;
} ms_verify_blob_t;

typedef struct ms_get_quote_t {
	uint32_t ms_retval;
	uint8_t* ms_p_blob;
	uint32_t ms_blob_size;
	const sgx_report_t* ms_p_report;
	sgx_quote_sign_type_t ms_quote_type;
	const sgx_spid_t* ms_p_spid;
	const sgx_quote_nonce_t* ms_p_nonce;
	const uint8_t* ms_p_sig_rl;
	uint32_t ms_sig_rl_size;
	sgx_report_t* ms_qe_report;
	uint8_t* ms_p_quote;
	uint32_t ms_quote_size;
	sgx_isv_svn_t ms_pce_isvnsvn;
} ms_get_quote_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL quoting_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL quoting_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL quoting_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL quoting_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL quoting_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_quoting_enclave = {
	5,
	{
		(void*)quoting_enclave_sgx_oc_cpuidex,
		(void*)quoting_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)quoting_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)quoting_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)quoting_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t verify_blob(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* p_blob, uint32_t blob_size, uint8_t* p_is_resealed, sgx_cpu_svn_t* p_cpusvn)
{
	sgx_status_t status;
	ms_verify_blob_t ms;
	ms.ms_p_blob = p_blob;
	ms.ms_blob_size = blob_size;
	ms.ms_p_is_resealed = p_is_resealed;
	ms.ms_p_cpusvn = p_cpusvn;
	status = sgx_ecall(eid, 0, &ocall_table_quoting_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_quote(sgx_enclave_id_t eid, uint32_t* retval, uint8_t* p_blob, uint32_t blob_size, const sgx_report_t* p_report, sgx_quote_sign_type_t quote_type, const sgx_spid_t* p_spid, const sgx_quote_nonce_t* p_nonce, const uint8_t* p_sig_rl, uint32_t sig_rl_size, sgx_report_t* qe_report, uint8_t* p_quote, uint32_t quote_size, sgx_isv_svn_t pce_isvnsvn)
{
	sgx_status_t status;
	ms_get_quote_t ms;
	ms.ms_p_blob = p_blob;
	ms.ms_blob_size = blob_size;
	ms.ms_p_report = p_report;
	ms.ms_quote_type = quote_type;
	ms.ms_p_spid = p_spid;
	ms.ms_p_nonce = p_nonce;
	ms.ms_p_sig_rl = p_sig_rl;
	ms.ms_sig_rl_size = sig_rl_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_quote = p_quote;
	ms.ms_quote_size = quote_size;
	ms.ms_pce_isvnsvn = pce_isvnsvn;
	status = sgx_ecall(eid, 1, &ocall_table_quoting_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

