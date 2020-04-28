/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "terminus_sched.h"
#include "enclave.h"
#include "routine.h"
#include "se_error_internal.h"
#include "xsave.h"
#include "rts_cmd.h"

typedef struct ms_ecall_init_AGENTS_t {
	sgx_status_t ms_retval;
	uint8_t* ms_heap_storage;
	uint8_t* ms_cfi_key;
	uint8_t* ms_meta_storage;
	void* ms_agent_status;
	uint8_t* ms_return_stack_storage;
	uint8_t* ms_ssas_storage;
	uint8_t* ms_debug_pointer;
} ms_ecall_init_AGENTS_t;

typedef struct _encl_thr_info_t{
    unsigned long  tid;
    int        agent_status; /* enclave_id */
    int        action;   
} encl_thr_info;

static encl_thr_info *agent_info = NULL;

static int init_sched = 0;
static
sgx_status_t _sgx_ecall(const sgx_enclave_id_t enclave_id, const int proc, const void *ocall_table, void *ms, const bool is_switchless)
{
    if (proc < 0)
    {
        return SGX_ERROR_INVALID_FUNCTION;
    }
    /****************
     * Terminus added code 
     * **************/
    uint64_t eid = acquire_enclave(enclave_id, proc, ECALL_IDX);
    /***************/
    CEnclave* enclave = CEnclavePool::instance()->ref_enclave(eid);
    if(proc == 0)
    {
        ms_ecall_init_AGENTS_t* tmp = (ms_ecall_init_AGENTS_t*)ms;
        agent_info = (encl_thr_info *) tmp->ms_agent_status;
        printf("%s:Agent info is at %p\n",__FUNCTION__, tmp->ms_agent_status);
        set_agent_info(tmp->ms_agent_status);
        set_debug_info(tmp->ms_debug_pointer);
        // If the scheduler is not initialized, initialize it
        set_ocall_table(ocall_table);
        // CTrustThread* cthread = enclave->get_free_tcs();
        // reg_aep_handler((uint64_t) cthread->get_tcs());
        init_sched = 1;
    }
    
    //If we failed to reference enclave, there is no corresponding enclave instance, so we didn't increase the enclave.m_ref;
    if(!enclave)
        return SGX_ERROR_INVALID_ENCLAVE_ID;

    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    if(proc >= 2)
    {
        agent_info->agent_status=1;
        result = enclave->ecall(proc, ocall_table, ms, is_switchless);
        agent_info->agent_status=0;
    }
    else
    {
        result = enclave->ecall(proc, ocall_table, ms, is_switchless);
    }
    {
        //This solution seems more readable and easy to validate, but low performace
        CEnclavePool::instance()->unref_enclave(enclave);
    }
    release_enclave(enclave_id, proc, ECALL_IDX);

    return result;
}

extern "C"
sgx_status_t sgx_ecall(const sgx_enclave_id_t enclave_id, const int proc, const void *ocall_table, void *ms)
{
    return _sgx_ecall(enclave_id, proc, ocall_table, ms, false);
}

extern "C"
sgx_status_t sgx_ecall_switchless(const sgx_enclave_id_t enclave_id, const int proc, const void *ocall_table, void *ms)
{
    return _sgx_ecall(enclave_id, proc, ocall_table, ms, true);
}

extern "C"
int sgx_ocall(const unsigned int proc, const sgx_ocall_table_t *ocall_table, void *ms, CTrustThread *trust_thread)
{
    int ret = 0;
    assert(trust_thread != NULL);
    CEnclave* enclave = trust_thread->get_enclave();
    release_enclave(enclave->get_enclave_id(), proc, OCALL_IDX);

    enclave->ocall(proc, ocall_table, ms);
    assert(enclave != NULL);
    /****************
     * Terminus added code 
     * **************/
    uint64_t eid = acquire_enclave(enclave->get_enclave_id(), proc, OCALL_IDX);
    (void) eid;
    /***************/
    return ret;
}
