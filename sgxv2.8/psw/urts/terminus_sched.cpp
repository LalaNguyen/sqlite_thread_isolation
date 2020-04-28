#include "terminus_sched.h"
#include "enclave.h"
#include <sys/time.h>

typedef struct enclave_status{
    long tid;
    int is_busy;
    unsigned long last_assigned;
} enclave_status_t;

typedef struct _encl_thr_info_t{
    unsigned long  tid;
    int        agent_status; /* enclave_id */
    int        action;   
} encl_thr_info;

typedef struct _enclave_thread_dbg{
    long  tid;
    unsigned int i;
    unsigned long i_address; 
    int occupied;
} enclave_thread_dbg;

const void * ocall_table = NULL;
encl_thr_info *agent_info = NULL;
enclave_thread_dbg *debug_info = NULL;

static pthread_mutex_t sched_mutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned int num_ECALL_swaps = 0;
static unsigned int num_OCALL_swaps = 0;
static unsigned int num_INT_swaps = 0;

/* Includes custom AEP get/set functions from patched SGX SDK urts. */
extern "C" void *sgx_aep_trampoline;
extern "C" void *sgx_default_aep_trampoline;
extern "C" void set_callback(void* cb);
uint64_t sgx_aep = 0x0;
uint64_t sgx_tcs = 0x0;
static int gdb_debug = 0;


enclave_status_t tracking_tabl[1] ={0,0,0};

uint64_t acquire_enclave(uint64_t eid, int call_idx, int call_type)
{
    uint64_t ret_eid = 999;
    while(ret_eid == 999)
    {
        ret_eid = get_free_enclave(eid, call_idx, call_type);
    }
    return ret_eid;
}

long get_current_active_tid()
{
    return tracking_tabl[0].tid;
}

void set_ocall_table(const void *tabl)
{
    ocall_table = tabl;
}

void set_agent_info(void *p)
{
    agent_info = (encl_thr_info *)p;
}

void set_debug_info(void *p)
{
    debug_info = (enclave_thread_dbg *)p;
}

void dump_swap_info()
{
    printf("Current ECALL_SWAPs is: %d\n", num_ECALL_swaps);
    printf("Current OCALL_SWAPs is: %d\n", num_OCALL_swaps);
    printf("Current INT_SWAPs is: %d\n", num_INT_swaps);

}
void dump_debug_info()
{
    printf("current i is : %d\n", debug_info->i);
    printf("address of i is : %lx\n", debug_info->i_address);
    printf("current occupied is : %d\n", debug_info->occupied);
    printf("current thread is : %ld\n", debug_info->tid);
}
void release_enclave(uint64_t eid, int call_idx, int call_type)
{
    pthread_mutex_lock(&sched_mutex);
    long tid = syscall(__NR_gettid);    
    (void) call_type;
    (void) call_idx;
    (void) eid;
    // if (call_type == ECALL_IDX)
    // {
    //     printf("[%ld] ECALL(id=%d) was returned. Unlock the enclave %lu\n", tid, call_idx, eid);
    // }
    // else
    // {
    //     printf("[%ld]        OCALL(id=%d) is made. Unlock the enclave %lu\n", tid,  call_idx, eid);
    // }
    if(tid == tracking_tabl[0].tid)
    {
        tracking_tabl[0].is_busy = 0;
    }
    else
    {
        printf("[%ld] Bug: Enclave is released but was not assigned to thread", tid);
    }
    pthread_mutex_unlock(&sched_mutex);
}

uint64_t get_free_enclave(uint64_t eid, int call_idx, int call_type)
{
    pthread_mutex_lock(&sched_mutex);
    uint64_t ret_eid = 999;
    long tid = syscall(__NR_gettid); 
    // struct timeval te;
    // If the thread was interrupted while the agent is still active
    if(tracking_tabl[0].is_busy && tid == tracking_tabl[0].tid)
    {
        ret_eid = eid;
    }
    else if(!tracking_tabl[0].is_busy)
    {   
        // gettimeofday(&te,NULL);
        // unsigned long elapsed = te.tv_sec*1000000+ te.tv_usec;
        // if( (elapsed - tracking_tabl[0].last_assigned) < 1000)
        // {
        //     if(tid == tracking_tabl[0].tid)
        //     {
        //         // printf("[%ld]  recatches the enclave\n", tid);
        //         ret_eid = eid;
        //         tracking_tabl[0].tid = tid;
        //         tracking_tabl[0].is_busy = 1;
        //         gettimeofday(&te,NULL);
        //         tracking_tabl[0].last_assigned = te.tv_sec*1000LL+ te.tv_usec/1000;
        //     }
        // }
        // else
        // {
             // printf("[%ld]        Enclave %ld is not busy\n", tid, eid);
            if(tracking_tabl[0].tid == 0)
            {
                // printf("[%ld]  Welcome to the shared enclave %ld. Total swaps = %d\n", tid, eid, num_ECALL_swaps);
            }
            if(tid != tracking_tabl[0].tid && (tracking_tabl[0].tid!=0) && call_type == 1)
            {
                //printf("[%ld]  Switching context for enclave %ld. Total swaps = %d\n", tid, eid, num_ECALL_swaps);
                num_ECALL_swaps++;
                //dump_debug_info();
            }
            else if(tid != tracking_tabl[0].tid && (tracking_tabl[0].tid!=0) && call_type == 0)
            {
                //printf("[%ld]  Switching context for enclave %ld. Return from OCALL. Total swaps = %d\n", tid, eid, num_OCALL_swaps);
                num_OCALL_swaps++;
                //dump_debug_info();
            }
            else if(tid != tracking_tabl[0].tid && (tracking_tabl[0].tid!=0) && call_type == 3)
            {
                //printf("[%ld]  Switching context for enclave %ld. Returning of an interrupted thread. Total swaps = %d\n", tid, eid, num_INT_swaps);
                CEnclave* enclave = CEnclavePool::instance()->ref_enclave(eid);
                sgx_set_aep((void*)&sgx_default_aep_trampoline);
                enclave->ecall(0x10, ocall_table, &tid);
                sgx_set_aep((void*)&sgx_aep_trampoline);
                num_INT_swaps ++;
                //dump_debug_info();
            }
            else if(tid == tracking_tabl[0].tid && (tracking_tabl[0].tid!=0) && call_type == 3)
            {
                // printf("[%ld]  Returning of an interrupted thread\n", tid);
            }
            if(num_ECALL_swaps >= 1990)
                dump_swap_info();
            ret_eid = eid;
            (void) call_idx;
            (void) call_type;
            /* Assign thread to enclave */
            tracking_tabl[0].tid = tid;
            tracking_tabl[0].is_busy = 1;
            // gettimeofday(&te,NULL);
            // tracking_tabl[0].last_assigned = te.tv_sec*1000000+ te.tv_usec;
        //}
    }
    pthread_mutex_unlock(&sched_mutex);
    return ret_eid;
}

void custom_aep_handler(void)
{    
    long tid = syscall(__NR_gettid); 
    if(agent_info->agent_status==0 && tracking_tabl[0].tid == tid)
    {
        release_enclave(0x2, 0, 1);
    }
    if(gdb_debug == 1)
        sgx_aep = (uint64_t) &sgx_default_aep_trampoline;
    /* acquire enclave to resume */
    uint64_t eid = acquire_enclave(0x2, 0, 3);
    (void) eid;
    asm volatile(   "mov sgx_tcs(%%rip), %%rbx  \n"/* TCS address */
                    "lea sgx_aep(%%rip), %%rax  \n"/* AEP address */
                    "mov (%%rax), %%rcx  \n"/* AEP address */
                            :
                            :
                            :"%rbx", "%rcx", "%rax");
                           /* Release the lock */
                    return;
}

void reg_aep_handler(uint64_t tcs)
{
    set_callback((void*)&custom_aep_handler);
    sgx_set_aep((void*)&sgx_aep_trampoline);
    sgx_aep = (uint64_t) &sgx_aep_trampoline;
    sgx_tcs = tcs;
}

