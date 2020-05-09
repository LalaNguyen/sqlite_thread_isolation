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


/**
 * File: trts_veh.cpp
 * Description: 
 *     This file implements the support of custom exception handling. 
 */

#include "sgx_trts_exception.h"
#include <stdlib.h>
#include "sgx_trts.h"
#include "xsave.h"
#include "arch.h"
#include "sgx_spinlock.h"
#include "thread_data.h"
#include "global_data.h"
#include "trts_internal.h"
#include "trts_inst.h"
#include "util.h"
#include "trts_util.h"
#include "trts_shared_constants.h"
#include "se_cdefs.h"
#include "AES.h"
#include "sgx_tseal.h" /* for sealing */
#include <string.h> /* for memcpy, memset */
/************
 * Data for swaps 
 *
*************/
#define NUMBER_OF_THREADS 10
#define RESERVE_REG(reg)  register int RR_##reg asm (#reg) \
                                 __attribute__((unused))

#define ECALL_SCHEDULE 0x10
#define ENABLE_SEALING 1
#define ENABLE_CFG_PROTECTION 1

typedef struct _encl_thr_info_t{
    unsigned long tid;
    int agent_status;
} encl_thr_info;

/* meta information that is used by the swap agent */
typedef struct thread_info{
    unsigned long thread_id;
    uint8_t *return_stack_location; /* agent */
    uint8_t *ssas_storage_entry; /* agent */
    uint8_t *private_storage_entry; /* agent */
    uint32_t ciph_priv_mem_size;
    uint32_t ciph_ssas_size;
    uint32_t ssas_size;
    uint32_t thread_stack_size;
    size_t agent_stack_size;
    size_t stack_at_launch_thread;
    thread_data_t thread_data;
    int is_initialized;
} thread_info_t;

/* agent info that is shared with the untrusted code to control the current execution state*/
static encl_thr_info *agent_info = (encl_thr_info *) malloc(sizeof(encl_thr_info));

/* the cfi key to protect against control flow hijacking */
static uint8_t *sealed_cfi_key = (uint8_t *) malloc(576);

/* Ciphertext and Plaintext are hardcoded at the moment */
static uint8_t global_plain_text[16] = {    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 
                                            0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
static const uint8_t global_hashed_string[16] = {   0x66, 0x7b, 0x4a, 0x8f, 0x59, 0x21, 0xd4, 0x66, 
                                                    0x30, 0x42, 0x6d, 0x94, 0xb0, 0x04, 0x1d, 0x00};
static uint8_t *cfi_key = (uint8_t *) malloc(16);
static uint8_t dec_data[16] = {0};

uint32_t g_meta_plain_size = sizeof(thread_info_t)*NUMBER_OF_THREADS;
static thread_info_t* g_current_thread_cache = (thread_info_t*) malloc(sizeof(thread_info_t));
static thread_info_t* ctx_table = (thread_info_t*) malloc(g_meta_plain_size); /* pointer table to ctx*/

/* global pointers to outside and inside storage */
static uint8_t *g_out_meta_storage_entry_p;  /* store agent metadata */
static uint8_t *g_out_return_stack_storage_p; /*store return stack of this enclave */
static uint8_t *g_out_ssas_storage_p; /*store return stack of this enclave */
static uint8_t *g_out_private_storage_p; /*store return stack of this enclave */
static uint8_t *g_out_agent_private_storage_p; /*store return stack of this enclave */
static uint8_t* g_in_tmp_ssas_buffer = (uint8_t*) malloc(0x8000);
static uint8_t* g_in_sealed_ssas = (uint8_t*) malloc(0x8000);
uint32_t g_ssa_size = SE_PAGE_SIZE;

/* Allocate tmp buffer for look aside buffer */
static uint8_t *g_in_sealed_private_mem_buffer = (uint8_t*) malloc(0xE000); /*store return stack of this enclave */
static uint8_t *g_in_tmp_private_mem_buffer = (uint8_t*) malloc(0xE000); /*store return stack of this enclave */
static uint8_t *g_in_private_mem_p;
static uint32_t g_private_mem_size;
static uint32_t g_config_size;
static uint8_t *g_lks_config;

/* Allocate buffers for encrypt/decrypt metadata*/
uint8_t *g_in_meta_plaintext = (uint8_t*) malloc(g_meta_plain_size);
uint32_t g_meta_ciph_size = sgx_calc_sealed_data_size(0,g_meta_plain_size);
uint8_t *g_in_sealed_metadata = (uint8_t*) malloc(g_meta_ciph_size);
uint32_t g_plain_return_stack_size = 4096;
uint32_t g_return_stack_ciph_size = sgx_calc_sealed_data_size(0, g_plain_return_stack_size);


/* Which thread is running ?*/
static unsigned long g_current_state = 0;

/******
 * For Sealing 
 *  * ******/
#include "sgx_tcrypto.h"
#include <math.h>
#include <sgx_utils.h>
#define FLAGS_NON_SECURITY_BITS     (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY| SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK     (~FLAGS_NON_SECURITY_BITS)
#define FLAGS_SECURITY_BITS_RESERVED (~(FLAGS_NON_SECURITY_BITS | SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG | SGX_FLAGS_KSS))
#define MISC_NON_SECURITY_BITS      0x0FFFFFFF  /* bit[27:0]: have no security implications */
#define TSEAL_DEFAULT_MISCMASK      (~MISC_NON_SECURITY_BITS)
#define KEY_POLICY_KSS  (SGX_KEYPOLICY_CONFIGID | SGX_KEYPOLICY_ISVFAMILYID | SGX_KEYPOLICY_ISVEXTPRODID)
#define MAX_CACHE_SIZE 0xE000
sgx_status_t my_seal_data(  const uint32_t additional_MACtext_length,
                            const uint8_t *p_additional_MACtext, const uint32_t text2encrypt_length,
                            const uint8_t *p_text2encrypt, const uint32_t sealed_data_size,
                            sgx_sealed_data_t *p_sealed_data)
{
    sgx_aes_gcm_128bit_key_t aes_key;
    sgx_status_t ret;
    (void) p_additional_MACtext;
    (void) sealed_data_size;
    (void) additional_MACtext_length;
    const sgx_report_t *report;
    /* Craft the key request */
    sgx_key_request_t key_request;
    memset(&key_request, 0, sizeof(sgx_key_request_t));
    
    /* sgx_seal_data */
    key_request.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
    key_request.attribute_mask.xfrm = 0x0;
    key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;

    report = sgx_self_report();
    if (report->body.attributes.flags & SGX_FLAGS_KSS)
    {
        key_request.key_policy = SGX_KEYPOLICY_MRSIGNER | KEY_POLICY_KSS;
    } 
    /*sgx_seal_data_ex*/
    uint8_t payload_iv[SGX_SEAL_IV_SIZE];
    memset(&payload_iv, 0, sizeof(payload_iv));
    memset(p_sealed_data, 0, sealed_data_size);

    ret = sgx_read_rand((unsigned char *)&(key_request.key_id), sizeof(sgx_key_id_t));
    assert(ret == SGX_SUCCESS);

    memcpy(&(key_request.cpu_svn), &(report->body.cpu_svn),sizeof(sgx_cpu_svn_t));
    memcpy(&(key_request.isv_svn), &(report->body.isv_svn),sizeof(sgx_isv_svn_t));
    key_request.config_svn = report->body.config_svn;
    key_request.key_name = SGX_KEYSELECT_SEAL;
    key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;
    key_request.misc_mask = TSEAL_DEFAULT_MISCMASK;

    /* sgx_seal_data_iv */
    ret = sgx_get_key((const sgx_key_request_t*)&key_request, &aes_key);
    assert(ret == SGX_SUCCESS);

   

    ret = sgx_rijndael128GCM_encrypt(&aes_key,p_text2encrypt,text2encrypt_length,
    reinterpret_cast<uint8_t *>(&(p_sealed_data->aes_data.payload)), payload_iv,SGX_SEAL_IV_SIZE,
    p_additional_MACtext, additional_MACtext_length,
    &(p_sealed_data->aes_data.payload_tag));

    if (ret == SGX_SUCCESS)
    {
        // Copy additional MAC text
        uint8_t* p_aad = NULL;
        if (additional_MACtext_length > 0)
        {
            p_aad = &(p_sealed_data->aes_data.payload[text2encrypt_length]);
            memcpy(p_aad, p_additional_MACtext, additional_MACtext_length);
        }

        // populate the plain_text_offset, payload_size in the data_blob
        p_sealed_data->plain_text_offset = text2encrypt_length;
        p_sealed_data->aes_data.payload_size = additional_MACtext_length + text2encrypt_length;
    }
    if (ret == SGX_SUCCESS)
    {
        // Copy data from the temporary key request buffer to the sealed data blob
        memcpy(&(p_sealed_data->key_request), &key_request, sizeof(sgx_key_request_t));
    }
    return ret;
}

sgx_status_t my_unseal_data(const sgx_sealed_data_t *p_sealed_data, uint8_t *p_additional_MACtext,
                            uint32_t *p_additional_MACtext_length, uint8_t *p_decrypted_text, uint32_t *p_decrypted_text_length)
{
    sgx_status_t err = SGX_ERROR_UNEXPECTED;
    sgx_aes_gcm_128bit_key_t aes_key;
    uint32_t decrypted_text_length = *p_decrypted_text_length;
    uint32_t add_text_length = sgx_get_add_mac_txt_len(p_sealed_data);
    (void) p_additional_MACtext_length;
    (void) p_additional_MACtext;
    uint8_t payload_iv[SGX_SEAL_IV_SIZE];
    memset(&payload_iv, 0, SGX_SEAL_IV_SIZE);
    // Retrieve the key request so we can draw the same
    err = sgx_get_key(&p_sealed_data->key_request, &aes_key);

    err = sgx_rijndael128GCM_decrypt( &aes_key, const_cast<uint8_t *>(p_sealed_data->aes_data.payload),
        decrypted_text_length, p_decrypted_text, &payload_iv[0], SGX_SEAL_IV_SIZE,
        const_cast<uint8_t *>(&(p_sealed_data->aes_data.payload[decrypted_text_length])), add_text_length,
        const_cast<sgx_aes_gcm_128bit_tag_t *>(&p_sealed_data->aes_data.payload_tag));
    return err;
}

/************
 * Functions for swaps 
 *
*************/

sgx_status_t unseal_g_metadata(){
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    memcpy(g_in_sealed_metadata, g_out_meta_storage_entry_p, g_meta_ciph_size);
    status = my_unseal_data((sgx_sealed_data_t*) g_in_sealed_metadata, NULL, NULL, g_in_meta_plaintext, &g_meta_plain_size);
    // Recover the context table
    memcpy(ctx_table, g_in_meta_plaintext, sizeof(thread_info_t)*NUMBER_OF_THREADS);    
    return status;
}

sgx_status_t  seal_and_clear_g_metadata(){
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    // backup the ctx table 
    memcpy((void*) g_in_meta_plaintext, (void*) ctx_table,  sizeof(thread_info_t)*NUMBER_OF_THREADS);
    status = my_seal_data(0, NULL, g_meta_plain_size, g_in_meta_plaintext, g_meta_ciph_size, (sgx_sealed_data_t *)g_in_sealed_metadata); 
    memcpy((void*)g_out_meta_storage_entry_p, (void*)g_in_sealed_metadata, g_meta_ciph_size);
    // Clear the ctx_table
    memset(ctx_table, 0,  sizeof(thread_info_t)*NUMBER_OF_THREADS);
    return status;
}


void *sgx_register_seal_key(uint8_t *user_key){
    memcpy(sealed_cfi_key, user_key, 576);
    return NULL;
}


void *sgx_register_meta_storage(uint8_t *storage){
    g_out_meta_storage_entry_p = storage;
   if(ENABLE_SEALING)
   {
        /* Seal the clean table */
        sgx_status_t status = SGX_ERROR_UNEXPECTED;
        memset(ctx_table, 0, sizeof(ctx_table));
        status = seal_and_clear_g_metadata();
        assert(status == 0);
   }
   else
   {
        memset(ctx_table, 0, sizeof(ctx_table));
   }
    memset(g_current_thread_cache, 0, sizeof(thread_info_t));
    return NULL;
}


void *sgx_register_return_stack_storage(uint8_t *storage){
    g_out_return_stack_storage_p = storage;
    return NULL;
}

void *sgx_register_ssas_storage(uint8_t *storage){
    g_out_ssas_storage_p = storage;
    return NULL;
}

void *sgx_register_private_data_storage(uint8_t *storage){
    g_out_private_storage_p = storage;
    return NULL;
}

void *sgx_register_private_mem(uint8_t *p,  uint32_t size, uint8_t *config, uint32_t lookaside_config_size){
    g_in_private_mem_p = p;
    g_lks_config = config;
    g_private_mem_size = size;
    g_config_size = lookaside_config_size;
    return NULL;
}

void *sgx_register_agent_status(void *status){
    agent_info = (encl_thr_info*) status;
    return NULL;
}

/* Agent saves the initial copy of the data first */
void *sgx_snapshot_private_mem(uint8_t *p){
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
      /* However, we need to backup the private memory storage */
    uint32_t ciph_priv_mem_size = 0;
    uint32_t plain_priv_mem_size = g_private_mem_size + g_config_size;
    ciph_priv_mem_size = sgx_calc_sealed_data_size(0, plain_priv_mem_size);
    memcpy(g_in_tmp_private_mem_buffer, p, g_private_mem_size);
    memcpy(g_in_tmp_private_mem_buffer + g_private_mem_size, g_lks_config, g_config_size);

    status = my_seal_data(  0, NULL, plain_priv_mem_size, (uint8_t*) g_in_tmp_private_mem_buffer, 
                            ciph_priv_mem_size, 
                            (sgx_sealed_data_t *) g_in_sealed_private_mem_buffer);
    assert(status == SGX_SUCCESS);
    /* Assign the start of the storage for the agent */
    g_out_agent_private_storage_p = g_out_private_storage_p;
    g_out_private_storage_p += MAX_CACHE_SIZE;
    /* Store the snapshot in agent storage */
    memcpy(g_out_agent_private_storage_p, g_in_sealed_private_mem_buffer, ciph_priv_mem_size);

    return NULL;
}

/* Given a target thread's ID, return its index number in the metadata table*/
int get_thread_idx(unsigned long target_idx)
{
    int idx = -1;
    for(unsigned int i = 0; i < NUMBER_OF_THREADS; i++)
    {
        if(ctx_table[i].thread_id == target_idx)
        {
            idx = i;
            break;
        }
    }
    return idx;
}

/* Crypto functions */
void copy_bytes(uint8_t *dst, uint8_t *src, int len){
    int i;
    for (i=0; i< len; i++){
      dst[i] = src[i];
    }
}

void encryptCBC128(uint8_t* state, int dlen, uint8_t* cipher){
    uint8_t tmp_iv[dlen] __attribute__ ((aligned (16)))  = {0};
    uint8_t tmp_state[dlen] __attribute__ ((aligned (16))) = {0};
    uint8_t *cipher_p = &cipher[0];
    uint8_t *iv_p = &tmp_iv[0];
    uint8_t *state_p = &tmp_state[0];
    copy_bytes(tmp_state, state, dlen);
    expandKey();
    for(int i = 0; i < dlen; i+=KEYLEN){
        XOR(iv_p, state_p);
        encryptAES128(state_p, cipher_p);
        iv_p = cipher_p;
        cipher_p += KEYLEN;
        state_p += KEYLEN;
    }
}
/**********
 * SGX Standard Functions
 * ***********/

typedef struct _handler_node_t
{
    uintptr_t callback;
    struct _handler_node_t   *next;
} handler_node_t;

static handler_node_t *g_first_node = NULL;
static sgx_spinlock_t g_handler_lock = SGX_SPINLOCK_INITIALIZER;

static uintptr_t g_veh_cookie = 0;
#define ENC_VEH_POINTER(x)  (uintptr_t)(x) ^ g_veh_cookie
#define DEC_VEH_POINTER(x)  (sgx_exception_handler_t)((x) ^ g_veh_cookie)


// sgx_register_exception_handler()
//      register a custom exception handler
// Parameter
//      is_first_handler - the order in which the handler should be called.
// if the parameter is nonzero, the handler is the first handler to be called.
// if the parameter is zero, the handler is the last handler to be called.
//      exception_handler - a pointer to the handler to be called.
// Return Value
//      handler - success
//         NULL - fail
void *sgx_register_exception_handler(int is_first_handler, sgx_exception_handler_t exception_handler)
{
    // initialize g_veh_cookie for the first time sgx_register_exception_handler is called.
    if(unlikely(g_veh_cookie == 0))
    {
        uintptr_t rand = 0;
        do
        {
            if(SGX_SUCCESS != sgx_read_rand((unsigned char *)&rand, sizeof(rand)))
            {
                return NULL;
            }
        } while(rand == 0);

        sgx_spin_lock(&g_handler_lock);
        if(g_veh_cookie == 0)
        {
            g_veh_cookie = rand;
        }
        sgx_spin_unlock(&g_handler_lock);
    }
    if(!sgx_is_within_enclave((const void*)exception_handler, 0))
    {
        return NULL;
    }
    handler_node_t *node = (handler_node_t *)malloc(sizeof(handler_node_t));
    if(!node)
    {
        return NULL;
    }
    node->callback = ENC_VEH_POINTER(exception_handler);

    // write lock
    sgx_spin_lock(&g_handler_lock);

    if((g_first_node == NULL) || is_first_handler)
    {
        node->next = g_first_node;
        g_first_node = node;
    }
    else
    {
        handler_node_t *tmp = g_first_node;
        while(tmp->next != NULL)
        {
            tmp = tmp->next;
        }
        node->next = NULL;
        tmp->next = node;
    }
    // write unlock
    sgx_spin_unlock(&g_handler_lock);

    return node;
}
// sgx_unregister_exception_handler()
//      unregister a custom exception handler.
// Parameter
//      handler - a handler to the custom exception handler previously 
// registered using the sgx_register_exception_handler function.
// Return Value
//      none zero - success
//              0 - fail
int sgx_unregister_exception_handler(void *handler)
{
    if(!handler)
    {
        return 0;
    }

    int status = 0;

    // write lock
    sgx_spin_lock(&g_handler_lock);

    if(g_first_node)
    {
        handler_node_t *node = g_first_node;
        if(node == handler)
        {
            g_first_node = node->next;
            status = 1;
        }
        else
        {
            while(node->next != NULL)
            {
                if(node->next == handler)
                {
                    node->next = node->next->next;
                    status = 1;
                    break;
                }
                node = node->next;
            }
        }
    }
    // write unlock
    sgx_spin_unlock(&g_handler_lock);

    if(status) free(handler);
    return status;
}

// continue_execution(sgx_exception_info_t *info):
//      try to restore the thread context saved in info to current execution context.
extern "C" __attribute__((regparm(1))) void continue_execution(sgx_exception_info_t *info);

// internal_handle_exception(sgx_exception_info_t *info):
//      the 2nd phrase exception handing, which traverse registered exception handlers.
//      if the exception can be handled, then continue execution
//      otherwise, throw abortion, go back to 1st phrase, and call the default handler.
extern "C" __attribute__((regparm(1))) void internal_handle_exception(sgx_exception_info_t *info)
{
    int status = EXCEPTION_CONTINUE_SEARCH;
    handler_node_t *node = NULL;
    thread_data_t *thread_data = get_thread_data();
    size_t size = 0;
    uintptr_t *nhead = NULL;
    uintptr_t *ntmp = NULL;
    uintptr_t xsp = 0;

    if (thread_data->exception_flag < 0)
        goto failed_end;
    thread_data->exception_flag++;

    // read lock
    sgx_spin_lock(&g_handler_lock);

    node = g_first_node;
    while(node != NULL)
    {
        size += sizeof(uintptr_t);
        node = node->next;
    }

    // There's no exception handler registered
    if (size == 0)
    {
        sgx_spin_unlock(&g_handler_lock);

        //exception cannot be handled
        // thread_data->exception_flag = -1;

        //instruction triggering the exception will be executed again.
        continue_execution(info);
    }

    if ((nhead = (uintptr_t *)malloc(size)) == NULL)
    {
        sgx_spin_unlock(&g_handler_lock);
        goto failed_end;
    }
    ntmp = nhead;
    node = g_first_node;
    while(node != NULL)
    {
        *ntmp = node->callback;
        ntmp++;
        node = node->next;
    }

    // read unlock
    sgx_spin_unlock(&g_handler_lock);

    // call exception handler until EXCEPTION_CONTINUE_EXECUTION is returned
    ntmp = nhead;
    while(size > 0)
    {
        sgx_exception_handler_t handler = DEC_VEH_POINTER(*ntmp);
        status = handler(info);
        if(EXCEPTION_CONTINUE_EXECUTION == status)
        {
            break;
        }
        ntmp++;
        size -= sizeof(sgx_exception_handler_t);
    }
    free(nhead);

    // call default handler
    // ignore invalid return value, treat to EXCEPTION_CONTINUE_SEARCH
    // check SP to be written on SSA is pointing to the trusted stack
    xsp = info->cpu_context.REG(sp);
    if (!is_valid_sp(xsp))
    {
        goto failed_end;
    }

    if(EXCEPTION_CONTINUE_EXECUTION == status)
    {
        //exception is handled, decrease the nested exception count
        thread_data->exception_flag--;
    }
    else
    {
        //exception cannot be handled
        thread_data->exception_flag = -1;
    }

    //instruction triggering the exception will be executed again.
    continue_execution(info);

failed_end:
    thread_data->exception_flag = -1; // mark the current exception cannot be handled
    abort();    // throw abortion
}

static int expand_stack_by_pages(void *start_addr, size_t page_count)
{
    int ret = -1;

    if ((start_addr == NULL) || (page_count == 0))
        return -1;

    ret = apply_pages_within_exception(start_addr, page_count);
    return ret;
}

extern "C" const char Lereport_inst;

// trts_handle_exception(void *tcs)
//      the entry point for the exceptoin handling
// Parameter
//      the pointer of TCS
// Return Value
//      none zero - success
//              0 - fail
extern "C" sgx_status_t trts_handle_exception(void *tcs)
{
    thread_data_t *thread_data = get_thread_data();
    ssa_gpr_t *ssa_gpr = NULL;
    sgx_exception_info_t *info = NULL;
    uintptr_t sp, *new_sp = NULL;
    size_t size = 0;

    if ((thread_data == NULL) || (tcs == NULL)) goto default_handler;
    if (check_static_stack_canary(tcs) != 0)
        goto default_handler;
 
    if(get_enclave_state() != ENCLAVE_INIT_DONE)
    {
        goto default_handler;
    }
    
    // check if the exception is raised from 2nd phrase
    if(thread_data->exception_flag == -1) {
        goto default_handler;
    }
 
    if ((TD2TCS(thread_data) != tcs) 
            || (((thread_data->first_ssa_gpr)&(~0xfff)) - SE_PAGE_SIZE) != (uintptr_t)tcs) {
        goto default_handler;
    }

    // no need to check the result of ssa_gpr because thread_data is always trusted
    ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr);
    
    sp = ssa_gpr->REG(sp);
    if(!is_stack_addr((void*)sp, 0))  // check stack overrun only, alignment will be checked after exception handled
    {
        g_enclave_state = ENCLAVE_CRASHED;
        return SGX_ERROR_STACK_OVERRUN;
    }

    size = 0;
    // x86_64 requires a 128-bytes red zone, which begins directly
    // after the return addr and includes func's arguments
    size += RED_ZONE_SIZE;

    // decrease the stack to give space for info
    size += sizeof(sgx_exception_info_t);
    sp -= size;
    sp = sp & ~0xF;

    // check the decreased sp to make sure it is in the trusted stack range
    if(!is_stack_addr((void *)sp, size))
    {
        g_enclave_state = ENCLAVE_CRASHED;
        return SGX_ERROR_STACK_OVERRUN;
    }

    info = (sgx_exception_info_t *)sp;
    // decrease the stack to save the SSA[0]->ip
    size = sizeof(uintptr_t);
    sp -= size;
    if(!is_stack_addr((void *)sp, size))
    {
        g_enclave_state = ENCLAVE_CRASHED;
        return SGX_ERROR_STACK_OVERRUN;
    }
    
    // sp is within limit_addr and commit_addr, currently only SGX 2.0 under hardware mode will enter this branch.^M
    if((size_t)sp < thread_data->stack_commit_addr)
    { 
        int ret = -1;
        size_t page_aligned_delta = 0;
        /* try to allocate memory dynamically */
        page_aligned_delta = ROUND_TO(thread_data->stack_commit_addr - (size_t)sp, SE_PAGE_SIZE);
        if ((thread_data->stack_commit_addr > page_aligned_delta)
                && ((thread_data->stack_commit_addr - page_aligned_delta) >= thread_data->stack_limit_addr))
        {
            ret = expand_stack_by_pages((void *)(thread_data->stack_commit_addr - page_aligned_delta), (page_aligned_delta >> SE_PAGE_SHIFT));
        }
        if (ret == 0)
        {
            thread_data->stack_commit_addr -= page_aligned_delta;
            return SGX_SUCCESS;
        }
        else
        {
            g_enclave_state = ENCLAVE_CRASHED;
            return SGX_ERROR_STACK_OVERRUN;
        }
    }
    if (size_t(&Lereport_inst) == ssa_gpr->REG(ip) && SE_EREPORT == ssa_gpr->REG(ax))
    {
        // Handle the exception raised by EREPORT instruction
        ssa_gpr->REG(ip) += 3;     // Skip ENCLU, which is always a 3-byte instruction
        ssa_gpr->REG(flags) |= 1;  // Set CF to indicate error condition, see implementation of do_report()
        return SGX_SUCCESS;
    }

    if(ssa_gpr->exit_info.valid != 1)
    {   // exception handlers are not allowed to call in a non-exception state
        goto default_handler;
    }

    // initialize the info with SSA[0]
    info->exception_vector = (sgx_exception_vector_t)ssa_gpr->exit_info.vector;
    info->exception_type = (sgx_exception_type_t)ssa_gpr->exit_info.exit_type;

    info->cpu_context.REG(ax) = ssa_gpr->REG(ax);
    info->cpu_context.REG(cx) = ssa_gpr->REG(cx);
    info->cpu_context.REG(dx) = ssa_gpr->REG(dx);
    info->cpu_context.REG(bx) = ssa_gpr->REG(bx);
    info->cpu_context.REG(sp) = ssa_gpr->REG(sp);
    info->cpu_context.REG(bp) = ssa_gpr->REG(bp);
    info->cpu_context.REG(si) = ssa_gpr->REG(si);
    info->cpu_context.REG(di) = ssa_gpr->REG(di);
    info->cpu_context.REG(flags) = ssa_gpr->REG(flags);
    info->cpu_context.REG(ip) = ssa_gpr->REG(ip);
#ifdef SE_64
    info->cpu_context.r8  = ssa_gpr->r8;
    info->cpu_context.r9  = ssa_gpr->r9;
    info->cpu_context.r10 = ssa_gpr->r10;
    info->cpu_context.r11 = ssa_gpr->r11;
    info->cpu_context.r12 = ssa_gpr->r12;
    info->cpu_context.r13 = ssa_gpr->r13;
    info->cpu_context.r14 = ssa_gpr->r14;
    info->cpu_context.r15 = ssa_gpr->r15;
#endif

    new_sp = (uintptr_t *)sp;
    ssa_gpr->REG(ip) = (size_t)internal_handle_exception; // prepare the ip for 2nd phrase handling
    ssa_gpr->REG(sp) = (size_t)new_sp;      // new stack for internal_handle_exception
    ssa_gpr->REG(ax) = (size_t)info;        // 1st parameter (info) for LINUX32
    ssa_gpr->REG(di) = (size_t)info;        // 1st parameter (info) for LINUX64, LINUX32 also uses it while restoring the context
    *new_sp = info->cpu_context.REG(ip);    // for debugger to get call trace
    
    //mark valid to 0 to prevent eenter again
    ssa_gpr->exit_info.valid = 0;

    return SGX_SUCCESS;
 
default_handler:
    g_enclave_state = ENCLAVE_CRASHED;
    return SGX_ERROR_ENCLAVE_CRASHED;
}

void inline fast_launch_thread(unsigned long target_thread_id, int index, void *ms, void *tcs)
{
    /* Reinit the thread again */
    do_init_thread(tcs,false);
    thread_data_t *thread_data = get_thread_data();
    size_t thread_stack_base = thread_data->stack_limit_addr + 0x20000;
    size_t enclave_rsp_base = 0;
    sgx_status_t status = SGX_SUCCESS;

    g_current_state = target_thread_id;
    enclave_rsp_base = thread_data->stack_base_addr + 0x1000;
    enclave_rsp_base &= ~0xFFF;

    /* make thread use new stack */
    asm volatile("xchg    %%rsp, %0\n"\
                    :"=m"(thread_stack_base)\
                    :
                    :);
    asm volatile("  mov %0, %%rax\n"::"m"(thread_stack_base):);
    asm volatile("  push %%rax\n":::);

    g_current_thread_cache->stack_at_launch_thread = thread_stack_base;
    g_current_thread_cache->agent_stack_size = enclave_rsp_base - g_current_thread_cache->stack_at_launch_thread;
    
    memcpy((void*) g_current_thread_cache->return_stack_location, (void*)(g_current_thread_cache->stack_at_launch_thread), g_current_thread_cache->agent_stack_size);

    assert(status == SGX_SUCCESS);
             
    status = do_terminus_ecall(index,ms);

    memcpy((void*) g_current_thread_cache->stack_at_launch_thread, (void*)(g_current_thread_cache->return_stack_location), g_current_thread_cache->agent_stack_size);
    /* resume the old stack */
    asm volatile("pop %%rax":::);
    asm volatile("nop");
    asm volatile("xchg    %%rax, %%rsp\n"\
                    :
                    :"m"(thread_stack_base)\
                    :);
}

void inline launch_thread(int thread_idx, unsigned long target_thread_id, int index, void *ms, void *tcs)
{
    (void) thread_idx;
    /* Reinit the thread again */
    do_init_thread(tcs,false);
    thread_data_t *thread_data = get_thread_data();
    size_t thread_stack_base = thread_data->stack_limit_addr + 0x20000;
    size_t enclave_rsp_base = 0;
    sgx_status_t status = SGX_SUCCESS;

    g_current_state = target_thread_id;
    enclave_rsp_base = thread_data->stack_base_addr + 0x1000;
    enclave_rsp_base &= ~0xFFF;

    /* make thread use new stack */
    asm volatile("xchg    %%rsp, %0\n"\
                    :"=m"(thread_stack_base)\
                    :
                    :);
    asm volatile("  mov %0, %%rax\n"::"m"(thread_stack_base):);
    asm volatile("  push %%rax\n":::);

    g_current_thread_cache->stack_at_launch_thread = thread_stack_base;
    g_current_thread_cache->agent_stack_size = enclave_rsp_base - g_current_thread_cache->stack_at_launch_thread;
    
    memcpy((void*) g_current_thread_cache->return_stack_location, (void*)(g_current_thread_cache->stack_at_launch_thread), g_current_thread_cache->agent_stack_size);

    assert(status == SGX_SUCCESS);
    
    if(ENABLE_CFG_PROTECTION)
    {
        /* Recompute MAC using the CFI key */
        asm volatile(   "movq %%r12,%%xmm5      \n"
                        "movq %%r13,%%xmm6      \n"   
                        "movlhps %%xmm5, %%xmm5 \n"
                        "por %%xmm6,%%xmm5     \n"  
                        :
                        :
                        :);
        
        memset(dec_data, 0, 16);
        encryptCBC128(global_plain_text, 16, dec_data);

        for (int k = 0; k < 16; k++)
        {
            if (dec_data[k] != global_hashed_string[k])
            {
                    abort();
            }
        }
            /* Clear r12, r13 */
        asm volatile(   "pxor %%xmm5,%%xmm5   \n"
                        "xor %%r12, %%r12     \n"   
                        "xor %%r13, %%r13     \n"
                        :
                        :
                        :);  
    }   
    
             
    status = do_ecall(index,ms,tcs);

    memcpy((void*) g_current_thread_cache->stack_at_launch_thread, (void*)(g_current_thread_cache->return_stack_location), g_current_thread_cache->agent_stack_size);
    /* resume the old stack */
    asm volatile("pop %%rax":::);
    asm volatile("nop");
    asm volatile("xchg    %%rax, %%rsp\n"\
                    :
                    :"m"(thread_stack_base)\
                    :);
}

void sgx_exception_routine(int cssa)
{
    thread_data_t *thread_data = NULL;
    /* Normal SGX exception routine */
    uintptr_t sp, *new_sp = NULL;
    sgx_exception_info_t *info = NULL;
    size_t size = 0;
    ssa_gpr_t *ssa_gpr = NULL;

    thread_data = get_thread_data();
    /* No need to check the result of ssa_gpr because thread_data is always trusted */
    ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr+(cssa-1)*0x1000);
    sp = ssa_gpr->REG(sp);
    if(!is_stack_addr((void*)sp, 0))  // check stack overrun only, alignment will be checked after exception handled
    {
        g_enclave_state = ENCLAVE_CRASHED;
        abort();
    }

    size = 0;
    // x86_64 requires a 128-bytes red zone, which begins directly
    // after the return addr and includes func's arguments
    size += RED_ZONE_SIZE;

    // decrease the stack to give space for info
    size += sizeof(sgx_exception_info_t);
    sp -= size;
    sp = sp & ~0xF;

    // check the decreased sp to make sure it is in the trusted stack range
    if(!is_stack_addr((void *)sp, size))
    {
        g_enclave_state = ENCLAVE_CRASHED;
        abort();
    }

    info = (sgx_exception_info_t *)sp;
    // decrease the stack to save the SSA[0]->ip
    size = sizeof(uintptr_t);
    sp -= size;
    if(!is_stack_addr((void *)sp, size))
    {
        g_enclave_state = ENCLAVE_CRASHED;
        abort();
    }

    // sp is within limit_addr and commit_addr, currently only SGX 2.0 under hardware mode will enter this branch.^M
    if((size_t)sp < thread_data->stack_commit_addr)
    { 
        int ret = -1;
        size_t page_aligned_delta = 0;
        /* try to allocate memory dynamically */
        page_aligned_delta = ROUND_TO(thread_data->stack_commit_addr - (size_t)sp, SE_PAGE_SIZE);
        if ((thread_data->stack_commit_addr > page_aligned_delta)
            && ((thread_data->stack_commit_addr - page_aligned_delta) >= thread_data->stack_limit_addr))
        {
            ret = expand_stack_by_pages((void *)(thread_data->stack_commit_addr - page_aligned_delta), (page_aligned_delta >> SE_PAGE_SHIFT));
        }
        if (ret == 0)
        {
            thread_data->stack_commit_addr -= page_aligned_delta;
            abort();
        }
        else
        {
            g_enclave_state = ENCLAVE_CRASHED;
            abort();
        }
    }

    // initialize the info with SSA[0]
    info->exception_vector = (sgx_exception_vector_t)ssa_gpr->exit_info.vector;
    info->exception_type = (sgx_exception_type_t)ssa_gpr->exit_info.exit_type;

    info->cpu_context.REG(ax) = ssa_gpr->REG(ax);
    info->cpu_context.REG(cx) = ssa_gpr->REG(cx);
    info->cpu_context.REG(dx) = ssa_gpr->REG(dx);
    info->cpu_context.REG(bx) = ssa_gpr->REG(bx);
    info->cpu_context.REG(sp) = ssa_gpr->REG(sp);
    info->cpu_context.REG(bp) = ssa_gpr->REG(bp);
    info->cpu_context.REG(si) = ssa_gpr->REG(si);
    info->cpu_context.REG(di) = ssa_gpr->REG(di);
    info->cpu_context.REG(flags) = ssa_gpr->REG(flags);
    info->cpu_context.REG(ip) = ssa_gpr->REG(ip);
    info->cpu_context.r8  = ssa_gpr->r8;
    info->cpu_context.r9  = ssa_gpr->r9;
    info->cpu_context.r10 = ssa_gpr->r10;
    info->cpu_context.r11 = ssa_gpr->r11;
    info->cpu_context.r12 = ssa_gpr->r12;
    info->cpu_context.r13 = ssa_gpr->r13;
    info->cpu_context.r14 = ssa_gpr->r14;
    info->cpu_context.r15 = ssa_gpr->r15;

    new_sp = (uintptr_t *)sp;
    ssa_gpr->REG(ip) = (size_t)internal_handle_exception; // prepare the ip for 2nd phrase handling
    ssa_gpr->REG(sp) = (size_t)new_sp;      // new stack for internal_handle_exception
    ssa_gpr->REG(ax) = (size_t)info;        // 1st parameter (info) for LINUX32
    ssa_gpr->REG(di) = (size_t)info;        // 1st parameter (info) for LINUX64, LINUX32 also uses it while restoring the context
    *new_sp = info->cpu_context.REG(ip);    // for debugger to get call trace
    
    //mark valid to 0 to prevent eenter again
    ssa_gpr->exit_info.valid = 0;
}

extern "C" sgx_status_t trts_swap_agent_handle_exception(void *tcs, int32_t index, void *ms, int cssa)
{
    RESERVE_REG(r12);
    RESERVE_REG(r13);
    size_t target_thread_id = 0;
    sgx_status_t status = SGX_ERROR_UNEXPECTED;
    /* Get target thread id */
    if(index == -1)
    {
        target_thread_id = *((unsigned long*)ms+1);
    }
    else
    {
        target_thread_id = *((unsigned long*)ms);
    }
   
    if(g_current_thread_cache->thread_id == target_thread_id)
    {
        if (index != ECMD_ORET && index != ECALL_SCHEDULE)
        {
            fast_launch_thread(target_thread_id, index, ms, tcs);
        }
        else if (index == ECMD_ORET)
        {
            status = do_oret(ms);
        }
        status = SGX_SUCCESS;
    }
    else
    {
        if(ENABLE_CFG_PROTECTION)
        {    
            // unseal the CFI key    
            uint32_t plaintext_len = 16;
            //status = sgx_unseal_data((sgx_sealed_data_t *) sealed_cfi_key, NULL, NULL, (uint8_t*)cfi_key, &plaintext_len);
            status = my_unseal_data((sgx_sealed_data_t *) sealed_cfi_key, NULL, NULL, (uint8_t*)cfi_key, &plaintext_len);
            assert(status == SGX_SUCCESS);
                
            // Load key to r12 & r13 register 
            asm volatile(   "lea (%0), %%rax          \n"
                            "movq (%%rax), %%r12      \n"
                            "movq 0x8(%%rax), %%r13  \n"
                            :
                            :"r"(cfi_key)
                            :"memory"); 
            // Clear the cfi key on memory 
            memset(cfi_key, 0, 16);
        }

        size_t thread_stack_base = 0;
        thread_data_t *thread_data = NULL;
        int thread_idx = -1;
        int prev_thread_idx = -1;
        void *current_thread_stack = NULL;
        ssa_gpr_t *ssa_gpr = NULL;

        thread_data = get_thread_data();
        assert(thread_data != NULL);

        thread_stack_base = thread_data->stack_limit_addr + 0x20000;
        size_t prev_thread_id_in_enclave = 0;

        
        if(g_current_thread_cache->thread_id != 0)
        {
            /* g_current_state != 0 when there is a previous thread in an enclave
            * It can be two cases:
            * 1. The same thread resumes in the enclave
            * 2. Different thread enters the enclave
            * In either cases, we check the thread cache to see if the target thread ID matches
            * the previous thread
            */
            prev_thread_id_in_enclave = g_current_thread_cache->thread_id ; 
            /* new thread enters the enclave, accessing the agent's metadata */
            /* Unseal metadata in enclave */
            if(ENABLE_SEALING)
            {
                status = unseal_g_metadata();
                assert(status == SGX_SUCCESS);
            }
            else
            {   
                status = SGX_SUCCESS;
            }
            /* Get idx of the current threads */
            prev_thread_idx = get_thread_idx(g_current_thread_cache->thread_id);
            /* If the current thread was not in the table, get it an index */
            if(prev_thread_idx == -1)
            {
                prev_thread_idx = get_thread_idx(0);
            }
            
            /* New thread is about to launch, save the stack */
            uint32_t prev_stack_size = 0;
            size_t curr_thread_sp = (size_t) thread_data->last_sp;
            /* always consider the size for an ssa even if it is empty */
            uint32_t ssas_size = 0;
            uint32_t ciph_ssas_size = 0;
            /* If new thread was launched on the cssa = 0 */
            if (cssa == 0)
            {
                /* previous call into an enclave was OCALL. Save thread stack based on the last_sp*/
                if(curr_thread_sp < (size_t) thread_stack_base)
                {
                    current_thread_stack = (void*) thread_data->last_sp;
                    prev_stack_size = (uint32_t) thread_stack_base -  (uint32_t) thread_data->last_sp;
                    // for debugging purpose 
                    ocall_context_t *context = reinterpret_cast<ocall_context_t*>(thread_data->last_sp);
                    (void) context;
                    ssas_size +=  prev_stack_size;
                    ciph_ssas_size = sgx_calc_sealed_data_size(0, ssas_size);
                    memcpy(g_in_tmp_ssas_buffer, (uint8_t*)current_thread_stack, prev_stack_size);
                    /* seal them to a common buffer */
                    status = my_seal_data(  0, NULL, prev_stack_size, (uint8_t*)g_in_tmp_ssas_buffer, 
                                        ciph_ssas_size, (sgx_sealed_data_t *)g_in_sealed_ssas); 
                    assert(status == SGX_SUCCESS);
                    memcpy(g_current_thread_cache->ssas_storage_entry, g_in_sealed_ssas, ciph_ssas_size);
                    g_current_thread_cache->ciph_ssas_size = ciph_ssas_size;
                    g_current_thread_cache->thread_stack_size = prev_stack_size;
                    g_current_thread_cache->ssas_size = ssas_size;
                }
                else 
                {
                    /* previous call into an enclave was ecall and cssa = 0. Meaning the thread has finished its enclave
                    execution. No need to save its stack*/
                    g_current_thread_cache->ciph_ssas_size = 0;
                    g_current_thread_cache->thread_stack_size = 0;
                    g_current_thread_cache->ssas_size = 0;
                    /* However, we need to backup the private memory storage */
                    uint32_t ciph_priv_mem_size = 0;
                    uint32_t plain_priv_mem_size = g_private_mem_size + g_config_size;
                    ciph_priv_mem_size = sgx_calc_sealed_data_size(0, plain_priv_mem_size);

                    memcpy(g_in_tmp_private_mem_buffer , g_in_private_mem_p, g_private_mem_size);
                    memcpy(g_in_tmp_private_mem_buffer+g_private_mem_size, g_lks_config, g_config_size);

                    status = my_seal_data(  0, NULL, plain_priv_mem_size, (uint8_t*) g_in_tmp_private_mem_buffer, 
                                        ciph_priv_mem_size, (sgx_sealed_data_t *) g_in_sealed_private_mem_buffer);

                    assert(status == SGX_SUCCESS);
                    memcpy(g_current_thread_cache->private_storage_entry, g_in_sealed_private_mem_buffer, ciph_priv_mem_size);
                    g_current_thread_cache->ciph_priv_mem_size = ciph_priv_mem_size;
                    /* Clear the private mem */
                    memset(g_in_private_mem_p, 0, g_private_mem_size);
                }
            }
            else 
            {
                ssa_gpr = reinterpret_cast<ssa_gpr_t *>(thread_data->first_ssa_gpr+(cssa-1)*0x1000);
                /* If new thread was launched on different cssa > 0, then two possiblities: 
                * - Previous thread was interrupted and this is the next thread to run
                * - Previous thread run at this cssa level, but has finished its enclave execution
                * TO distinguish between them, we rely on the rip, since non-interrupted thread 
                * would not be recorded in SSA
                * *******************************************************************/
                if(ssa_gpr->rip!=0)
                {
                    /* If the previous ecall was interrupted */
                    ssas_size += g_ssa_size; // interrupted thread always have ssa
                    current_thread_stack = (void*) ssa_gpr->REG(sp);
                    prev_stack_size = (uint32_t) thread_stack_base -  (uint32_t) ssa_gpr->REG(sp);
                    ssas_size += prev_stack_size;
                    ciph_ssas_size = sgx_calc_sealed_data_size(0, ssas_size);
                    memcpy(g_in_tmp_ssas_buffer, (uint8_t*)((unsigned long) ssa_gpr & ~0xFFF), g_ssa_size); /* an SSA frame is page aligned */
                    memcpy(g_in_tmp_ssas_buffer + g_ssa_size, (uint8_t*)current_thread_stack, prev_stack_size);
                    status = my_seal_data(  0, NULL, ssas_size, (uint8_t*)g_in_tmp_ssas_buffer, 
                                            ciph_ssas_size, (sgx_sealed_data_t *)g_in_sealed_ssas); 
                    assert(status == SGX_SUCCESS);
                    memcpy(g_current_thread_cache->ssas_storage_entry, g_in_sealed_ssas, ciph_ssas_size);
                    g_current_thread_cache->ciph_ssas_size = ciph_ssas_size;
                    g_current_thread_cache->thread_stack_size = prev_stack_size;
                    g_current_thread_cache->ssas_size = ssas_size;
                    memset(ssa_gpr, 0, sizeof(sgx_cpu_context_t));
                }
                else
                {
                    /* previous call into an enclave was ecall and cssa != 0. Meaning the thread has finished 
                    its enclave execution. No need to save its stack*/                    
                    g_current_thread_cache->ciph_ssas_size = 0;
                    g_current_thread_cache->thread_stack_size = 0;
                    g_current_thread_cache->ssas_size = 0;
                }
            }
            memcpy((void*)&g_current_thread_cache->thread_data, (void*)thread_data,sizeof(thread_data_t));
            /* Update the thread cache */
            memcpy(&ctx_table[prev_thread_idx], g_current_thread_cache, sizeof(thread_info_t));
            /* Get its index in the metadata table */
            /* -1 means that the thread is new, otherwise it is an old thread that agent has seen before*/
            thread_idx = get_thread_idx(target_thread_id);
            if (thread_idx != -1)
            {
                /* Switch to new thread cache */
                memcpy(g_current_thread_cache, &ctx_table[thread_idx], sizeof(thread_info_t));
                /* Recover its private data */
                memcpy( g_in_sealed_private_mem_buffer, 
                        g_current_thread_cache->private_storage_entry, 
                        g_current_thread_cache->ciph_priv_mem_size);
                
                uint32_t plain_size = g_config_size + g_private_mem_size;
                status = my_unseal_data((sgx_sealed_data_t *) g_in_sealed_private_mem_buffer, NULL, NULL, 
                                        (uint8_t*)g_in_tmp_private_mem_buffer, (uint32_t*)&plain_size);

                memcpy(g_in_private_mem_p, g_in_tmp_private_mem_buffer, g_private_mem_size);
                memcpy(g_lks_config, g_in_tmp_private_mem_buffer+g_private_mem_size, g_config_size);
                assert(status == SGX_SUCCESS);
            }
            else
            {
                memset(g_current_thread_cache, 0, sizeof(thread_info_t));
                g_current_thread_cache->thread_id = target_thread_id;
                /* Reinit the thread again */
                do_init_thread(tcs,false);
                /* Recover the initial cache state */
                uint32_t ciph_priv_mem_size = 0;
                uint32_t plain_size = g_config_size + g_private_mem_size;
                ciph_priv_mem_size = sgx_calc_sealed_data_size(0, plain_size);
                memcpy( g_in_sealed_private_mem_buffer, 
                        g_out_agent_private_storage_p, 
                        ciph_priv_mem_size);
                status = my_unseal_data((sgx_sealed_data_t *) g_in_sealed_private_mem_buffer, NULL, NULL, 
                                        (uint8_t*)g_in_tmp_private_mem_buffer, (uint32_t*)&plain_size);
                assert(status == SGX_SUCCESS);
                memcpy(g_in_private_mem_p, g_in_tmp_private_mem_buffer, g_private_mem_size);
                memcpy(g_lks_config, g_in_tmp_private_mem_buffer+g_private_mem_size, g_config_size);
            }
            /* We are done with the metatable, seal it and clear it */
            if(ENABLE_SEALING)
            {
                seal_and_clear_g_metadata();
            }
        }
        else
        {   /* Very first thread enters enclave, unseal the ctx_table */
            if(ENABLE_SEALING)
            {
                status = unseal_g_metadata();
                assert(status == SGX_SUCCESS);
            }
            else
            {   
                status = SGX_SUCCESS;
            }
            g_current_thread_cache->thread_id = target_thread_id;
            memcpy((void*)&g_current_thread_cache->thread_data, (void*)thread_data,sizeof(thread_data_t));
        }
        
        /* If the thread is not initialized, the thread claims the resource */
        if(g_current_thread_cache->is_initialized == 0)
        {
            g_current_thread_cache->return_stack_location = g_out_return_stack_storage_p;
            g_current_thread_cache->ssas_storage_entry = g_out_ssas_storage_p;
            g_current_thread_cache->private_storage_entry= g_out_private_storage_p;
            g_out_return_stack_storage_p += g_return_stack_ciph_size;
            g_out_private_storage_p += MAX_CACHE_SIZE;
            g_out_ssas_storage_p += 5*SE_PAGE_SIZE;
            g_current_thread_cache->is_initialized = 1;
        }



        if (index != ECMD_ORET && index != ECALL_SCHEDULE)
        {
            launch_thread(thread_idx, target_thread_id, index, ms, tcs);
        }
        else if (index == ECMD_ORET)
        {
            if(g_current_thread_cache->thread_id == prev_thread_id_in_enclave)
            {

            }
            else
            {
                // Recover thread_data
                memcpy((void*)thread_data, (void*)&g_current_thread_cache->thread_data, sizeof(thread_data_t));
                //Swap with target thread's context
                // Recover stack
                if(g_current_thread_cache->ciph_ssas_size != 0)
                {
                    memcpy(g_in_sealed_ssas, g_current_thread_cache->ssas_storage_entry, g_current_thread_cache->ciph_ssas_size);
                    status = my_unseal_data((sgx_sealed_data_t *) g_in_sealed_ssas, NULL, NULL, 
                                            (uint8_t*)g_in_tmp_ssas_buffer, &g_current_thread_cache->ssas_size);
                    assert(status == SGX_SUCCESS);
                    current_thread_stack = (void*) thread_data->last_sp;
                    memcpy(current_thread_stack, g_in_tmp_ssas_buffer, g_current_thread_cache->thread_stack_size);
                }        
                // for debugging purpose 
                ocall_context_t *context = reinterpret_cast<ocall_context_t*>(thread_data->last_sp);
                (void) context;
                // Update thread id
                g_current_state = target_thread_id;
                /* End of the swap agent */
                {
                    /* Recompute MAC using the CFI key */
                    asm volatile(   "movq %%r12,%%xmm5      \n"
                                    "movq %%r13,%%xmm6      \n"   
                                    "movlhps %%xmm5, %%xmm5 \n"
                                    "por %%xmm6,%%xmm5     \n"  
                                    :
                                    :
                                    :);
                    memset(dec_data, 0, 16);

                    encryptCBC128(global_plain_text, 16, dec_data);

                    for (int k = 0; k < 16; k++){
                        if (dec_data[k] != global_hashed_string[k]){
                            return SGX_ERROR_ECALL_NOT_ALLOWED;
                        }
                    }
                    /* Clear r12, r13 */
                    asm volatile(   "pxor %%xmm5,%%xmm5   \n"
                                    "xor %%r12, %%r12     \n"   
                                    "xor %%r13, %%r13     \n"
                                    :
                                    :
                                    :);
                }
            }
            status = do_oret(ms);
        }
        else if (index ==ECALL_SCHEDULE)
        {
            // There are two scenarios: 
            // 1. A thread was preempted and new thread running on top in this interrupted SSA
            // 1.1 A thread runs again in this SSA
            // 2. A thread finished its execution and a new thread running on top, there is still an interrupted context
                /* Resume a previously interrupted thread */
                /* We have to handle 3 types of thread here:
                    * 1. Thread to be resumed
                    * 2. Thread was interrupted
                    * 3. Thread at cssa -1 
                    */
            memcpy((void*)thread_data, (void*)&g_current_thread_cache->thread_data, sizeof(thread_data_t));
            // Recover thread on the last index 

            // Prepare CPU enclave context for previous cssa
            memcpy(g_in_sealed_ssas, g_current_thread_cache->ssas_storage_entry, g_current_thread_cache->ciph_ssas_size);
            status = my_unseal_data((sgx_sealed_data_t *) g_in_sealed_ssas, NULL, NULL, (uint8_t*)g_in_tmp_ssas_buffer, &g_current_thread_cache->ssas_size);
            assert(status == SGX_SUCCESS);
            
            /* Get CPU context first, then we can obtain the current stack pointer */
            memcpy((uint8_t*)((unsigned long) ssa_gpr & ~0xFFF), g_in_tmp_ssas_buffer, g_ssa_size);
            current_thread_stack = (void*)ssa_gpr->REG(sp);
            memcpy((uint8_t*)current_thread_stack, g_in_tmp_ssas_buffer + g_ssa_size, g_current_thread_cache->thread_stack_size);
            
            g_current_state = target_thread_id;

            /* End of the swap agent */
            {
                /* Recompute MAC using the CFI key */
                asm volatile(   "movq %%r12,%%xmm5      \n"
                                "movq %%r13,%%xmm6      \n"   
                                "movlhps %%xmm5, %%xmm5 \n"
                                "por %%xmm6,%%xmm5     \n"  
                                :
                                :
                                :);
                memset(dec_data, 0, 16);

                encryptCBC128(global_plain_text, 16, dec_data);

                for (int k = 0; k < 16; k++){
                    if (dec_data[k] != global_hashed_string[k]){
                        return SGX_ERROR_ECALL_NOT_ALLOWED;
                    }
                }
                /* Clear r12, r13 */
                asm volatile(   "pxor %%xmm5,%%xmm5   \n"
                                "xor %%r12, %%r12     \n"   
                                "xor %%r13, %%r13     \n"
                                :
                                :
                                :);
            }
            sgx_exception_routine(cssa);                
        }
        else    /* Should never reach here */ 
            abort();   
    }
    return status;
}

