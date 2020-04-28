#ifndef PROVISION_ENCLAVE_U_H__
#define PROVISION_ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "provision_msg.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t gen_prov_msg1_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, const extended_epid_group_blob_t* xegb, const signed_pek_t* pek, const sgx_target_info_t* pce_target_info, sgx_report_t* msg1_output);
sgx_status_t proc_prov_msg2_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, const proc_prov_msg2_blob_input_t* msg2_input, uint8_t performance_rekey_used, const uint8_t* sigrl, uint32_t sigrl_size, gen_prov_msg3_output_t* msg3_fixed_output, uint8_t* epid_sig, uint32_t epid_sig_buffer_size);
sgx_status_t proc_prov_msg4_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, const proc_prov_msg4_input_t* msg4_input, proc_prov_msg4_output_t* data_blob);
sgx_status_t gen_es_msg1_data_wrapper(sgx_enclave_id_t eid, uint32_t* retval, gen_endpoint_selection_output_t* es_output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
