#define SEALED_CFI_KEY_SIZE 576
#define KEYLEN 16

typedef struct _encl_thr_info_t{
    unsigned long tid;
    int agent_status;
} encl_thr_info;

static uint8_t sealed_cfi_key[576] = {0};
static encl_thr_info *agent_info;

typedef struct _enclave_thread_dbg{
    long  tid;
    unsigned int i; 
    unsigned long i_address;
    int occupied;
} enclave_thread_dbg;