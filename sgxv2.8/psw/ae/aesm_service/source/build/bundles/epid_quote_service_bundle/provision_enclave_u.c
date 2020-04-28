#include "provision_enclave_u.h"
#include <errno.h>

typedef struct ms_gen_prov_msg1_data_wrapper_t {
	uint32_t ms_retval;
	const extended_epid_group_blob_t* ms_xegb;
	const signed_pek_t* ms_pek;
	const sgx_target_info_t* ms_pce_target_info;
	sgx_report_t* ms_msg1_output;
} ms_gen_prov_msg1_data_wrapper_t;

typedef struct ms_proc_prov_msg2_data_wrapper_t {
	uint32_t ms_retval;
	const proc_prov_msg2_blob_input_t* ms_msg2_input;
	uint8_t ms_performance_rekey_used;
	const uint8_t* ms_sigrl;
	uint32_t ms_sigrl_size;
	gen_prov_msg3_output_t* ms_msg3_fixed_output;
	uint8_t* ms_epid_sig;
	uint32_t ms_epid_sig_buffer_size;
} ms_proc_prov_msg2_data_wrapper_t;

typedef struct ms_proc_prov_msg4_data_wrapper_t {
	uint32_t ms_retval;
	const proc_prov_msg4_input_t* ms_msg4_input;
	proc_prov_msg4_output_t* ms_data_blob;
} ms_proc_prov_msg4_data_wrapper_t;

typedef struct ms_gen_es_msg1_data_wrapper_t {
	uint32_t ms_retval;
	gen_endpoint_selection_output_t* ms_es_output;
} ms_gen_es_msg1_data_wrapper_t;

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

static sgx_status_t SGX_CDECL provision_enclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL provision_enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL provision_enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL provision_enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL provision_enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_provision_enclave = {
	5,
	{
		(void*)provision_enclave_sgx_oc_cpuidex,
		(void*)provision_enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)provision_enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)provision_enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)provision_enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t gen_prov_msg1_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, const extended_epid_group_blob_t* xegb, const signed_pek_t* pek, const sgx_target_info_t* pce_target_info, sgx_report_t* msg1_output)
{
	sgx_status_t status;
	ms_gen_prov_msg1_data_wrapper_t ms;
	ms.ms_xegb = xegb;
	ms.ms_pek = pek;
	ms.ms_pce_target_info = pce_target_info;
	ms.ms_msg1_output = msg1_output;
	status = sgx_ecall(eid, 0, &ocall_table_provision_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t proc_prov_msg2_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, const proc_prov_msg2_blob_input_t* msg2_input, uint8_t performance_rekey_used, const uint8_t* sigrl, uint32_t sigrl_size, gen_prov_msg3_output_t* msg3_fixed_output, uint8_t* epid_sig, uint32_t epid_sig_buffer_size)
{
	sgx_status_t status;
	ms_proc_prov_msg2_data_wrapper_t ms;
	ms.ms_msg2_input = msg2_input;
	ms.ms_performance_rekey_used = performance_rekey_used;
	ms.ms_sigrl = sigrl;
	ms.ms_sigrl_size = sigrl_size;
	ms.ms_msg3_fixed_output = msg3_fixed_output;
	ms.ms_epid_sig = epid_sig;
	ms.ms_epid_sig_buffer_size = epid_sig_buffer_size;
	status = sgx_ecall(eid, 1, &ocall_table_provision_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t proc_prov_msg4_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, const proc_prov_msg4_input_t* msg4_input, proc_prov_msg4_output_t* data_blob)
{
	sgx_status_t status;
	ms_proc_prov_msg4_data_wrapper_t ms;
	ms.ms_msg4_input = msg4_input;
	ms.ms_data_blob = data_blob;
	status = sgx_ecall(eid, 2, &ocall_table_provision_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t gen_es_msg1_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, gen_endpoint_selection_output_t* es_output)
{
	sgx_status_t status;
	ms_gen_es_msg1_data_wrapper_t ms;
	ms.ms_es_output = es_output;
	status = sgx_ecall(eid, 3, &ocall_table_provision_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

