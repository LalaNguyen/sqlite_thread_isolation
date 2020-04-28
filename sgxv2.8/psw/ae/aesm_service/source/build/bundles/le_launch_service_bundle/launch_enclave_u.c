#include "launch_enclave_u.h"
#include <errno.h>

typedef struct ms_le_get_launch_token_wrapper_t {
	int ms_retval;
	const sgx_measurement_t* ms_mrenclave;
	const sgx_measurement_t* ms_mrsigner;
	const sgx_attributes_t* ms_se_attributes;
	token_t* ms_lictoken;
} ms_le_get_launch_token_wrapper_t;

typedef struct ms_le_init_white_list_wrapper_t {
	uint32_t ms_retval;
	const uint8_t* ms_wl_cert_chain;
	uint32_t ms_wl_cert_chain_size;
} ms_le_init_white_list_wrapper_t;

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

static sgx_status_t SGX_CDECL launch_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL launch_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL launch_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL launch_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL launch_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_launch_enclave = {
	5,
	{
		(void*)launch_enclave_sgx_oc_cpuidex,
		(void*)launch_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)launch_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)launch_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)launch_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t le_get_launch_token_wrapper(sgx_enclave_id_t eid, int* retval, const sgx_measurement_t* mrenclave, const sgx_measurement_t* mrsigner, const sgx_attributes_t* se_attributes, token_t* lictoken)
{
	sgx_status_t status;
	ms_le_get_launch_token_wrapper_t ms;
	ms.ms_mrenclave = mrenclave;
	ms.ms_mrsigner = mrsigner;
	ms.ms_se_attributes = se_attributes;
	ms.ms_lictoken = lictoken;
	status = sgx_ecall(eid, 0, &ocall_table_launch_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t le_init_white_list_wrapper(sgx_enclave_id_t eid, uint32_t* retval, const uint8_t* wl_cert_chain, uint32_t wl_cert_chain_size)
{
	sgx_status_t status;
	ms_le_init_white_list_wrapper_t ms;
	ms.ms_wl_cert_chain = wl_cert_chain;
	ms.ms_wl_cert_chain_size = wl_cert_chain_size;
	status = sgx_ecall(eid, 1, &ocall_table_launch_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

