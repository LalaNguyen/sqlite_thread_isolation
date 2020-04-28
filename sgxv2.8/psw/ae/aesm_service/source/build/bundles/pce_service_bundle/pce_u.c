#include "pce_u.h"
#include <errno.h>

typedef struct ms_get_pc_info_t {
	uint32_t ms_retval;
	const sgx_report_t* ms_report;
	const uint8_t* ms_public_key;
	uint32_t ms_key_size;
	uint8_t ms_crypto_suite;
	uint8_t* ms_encrypted_ppid;
	uint32_t ms_encrypted_ppid_buf_size;
	uint32_t* ms_encrypted_ppid_out_size;
	pce_info_t* ms_pce_info;
	uint8_t* ms_signature_scheme;
} ms_get_pc_info_t;

typedef struct ms_certify_enclave_t {
	uint32_t ms_retval;
	const psvn_t* ms_cert_psvn;
	const sgx_report_t* ms_report;
	uint8_t* ms_signature;
	uint32_t ms_signature_buf_size;
	uint32_t* ms_signature_out_size;
} ms_certify_enclave_t;

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

static sgx_status_t SGX_CDECL pce_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pce_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pce_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pce_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL pce_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_pce = {
	5,
	{
		(void*)pce_sgx_oc_cpuidex,
		(void*)pce_sgx_thread_wait_untrusted_event_ocall,
		(void*)pce_sgx_thread_set_untrusted_event_ocall,
		(void*)pce_sgx_thread_setwait_untrusted_events_ocall,
		(void*)pce_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t get_pc_info(sgx_enclave_id_t eid, uint32_t* retval, const sgx_report_t* report, const uint8_t* public_key, uint32_t key_size, uint8_t crypto_suite, uint8_t* encrypted_ppid, uint32_t encrypted_ppid_buf_size, uint32_t* encrypted_ppid_out_size, pce_info_t* pce_info, uint8_t* signature_scheme)
{
	sgx_status_t status;
	ms_get_pc_info_t ms;
	ms.ms_report = report;
	ms.ms_public_key = public_key;
	ms.ms_key_size = key_size;
	ms.ms_crypto_suite = crypto_suite;
	ms.ms_encrypted_ppid = encrypted_ppid;
	ms.ms_encrypted_ppid_buf_size = encrypted_ppid_buf_size;
	ms.ms_encrypted_ppid_out_size = encrypted_ppid_out_size;
	ms.ms_pce_info = pce_info;
	ms.ms_signature_scheme = signature_scheme;
	status = sgx_ecall(eid, 0, &ocall_table_pce, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t certify_enclave(sgx_enclave_id_t eid, uint32_t* retval, const psvn_t* cert_psvn, const sgx_report_t* report, uint8_t* signature, uint32_t signature_buf_size, uint32_t* signature_out_size)
{
	sgx_status_t status;
	ms_certify_enclave_t ms;
	ms.ms_cert_psvn = cert_psvn;
	ms.ms_report = report;
	ms.ms_signature = signature;
	ms.ms_signature_buf_size = signature_buf_size;
	ms.ms_signature_out_size = signature_out_size;
	status = sgx_ecall(eid, 1, &ocall_table_pce, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

