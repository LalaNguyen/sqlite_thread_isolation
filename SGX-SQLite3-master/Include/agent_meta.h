#ifndef _APP_AGENT_H_
#define _APP_AGENT_H_
#include <stdlib.h>
#include <stdarg.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#define NUMBER_OF_ENCLAVES  1

typedef struct _encl_thr_info_t{
    unsigned long  tid;
    int        agent_status; /* enclave_id */
    int        action;   
} encl_thr_info;

typedef struct _per_enclave_meta{
    encl_thr_info *thread_info;
    short          busy_bit;
    uint8_t         *sealed_heap_storage;
    uint8_t         *sealed_meta_storage;
    uint8_t         *sealed_return_stack_storage;
    uint8_t         *sealed_ssas_storage;
    sgx_enclave_id_t eid;
    uint8_t         *cfi_key;

} per_enclave_meta;


typedef struct _enclave_thread_dbg{
    long  tid;
    unsigned int i; 
    unsigned long i_address;
    int occupied;
} enclave_thread_dbg;

per_enclave_meta *encl_arr[NUMBER_OF_ENCLAVES] = {0};

static uint8_t cfi_key[16]={      0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

#define MAX_PATH FILENAME_MAX
#define HS_STORAGE_SIZE 0x120000
#define META_STORAGE_SIZE 0x20000
#define SSA_STORAGE_SIZE 0x80000
#define RS_STORAGE_SIZE 0x40000

extern per_enclave_meta *encl_arr[NUMBER_OF_ENCLAVES];

#if defined(__cplusplus)
extern "C" {
#endif


#if defined(__cplusplus)
}
#endif

#endif