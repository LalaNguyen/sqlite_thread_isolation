
#ifndef _TERMINUS_SCHED_H_
#define _TERMINUS_SCHED_H_

typedef unsigned long      uint64_t;

#define ECALL_IDX 1
#define OCALL_IDX 0

uint64_t acquire_enclave(uint64_t eid, int call_idx, int call_type);
uint64_t get_free_enclave(uint64_t eid, int call_idx, int call_type);
void release_enclave(uint64_t eid, int call_idx, int call_type);
long get_current_active_tid();
void set_ocall_table(const void *tabl);
void set_agent_info(void *p);
void set_debug_info(void *p);

void reg_aep_handler(uint64_t);
void custom_aep_handler(void);
#endif
