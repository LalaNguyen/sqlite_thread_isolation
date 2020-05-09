#include "sgx_urts.h"
#include "Enclave_u.h"
#include <iostream>
#include <string>
#include <pthread.h>
#include <unistd.h>
#include "agent_meta.h"
#include <sys/time.h>

#define __NR_gettid 186
# define MAX_PATH FILENAME_MAX
# define ENCLAVE_FILENAME "enclave.signed.so"
#define NUM_THREADS 5
#define NUM_ENCLAVES 1
#define SEALED_CFI_KEY_SIZE 576
#define KEYLEN 16


static uint8_t sealed_cfi_key[576] = {0};
static encl_thr_info *agent_info;
static enclave_thread_dbg* e1 = (enclave_thread_dbg*) malloc (sizeof(enclave_thread_dbg));

// ocalls for printing string (C++ ocalls)
void ocall_print_error(const char *str) {
  std::cerr << str << std::endl;
}

void ocall_print_string(const char *str) {
  long tid = syscall(__NR_gettid); 
  printf("[%ld] %s \n", tid, str);
}

void ocall_println_string(const char *str) {
  std::cout << str << std::endl;
}

void ocall_my_print_string(long tid, const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void *walthread1_thread(void *enclave_id)
{
  int nIter = 0;
  long tid = syscall(__NR_gettid);
  struct timeval tvalBefore, tvalAfter;
  unsigned int exec_time = 0; 
  printf("[%ld] === Thread BEGIN === \n", tid);
  sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls
  const char *azSql[] = {
      "SELECT md5sum(x) FROM t1 WHERE rowid != (SELECT max(rowid) FROM t1)",
    };
  while(nIter < 10)
  {
    // /* Read */
    // gettimeofday (&tvalBefore, NULL);
    ret = ecall_terminus_execute_sql(*(int*)enclave_id, tid, azSql[0]);
    // gettimeofday (&tvalAfter, NULL);
    // exec_time = (((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000 + tvalAfter.tv_usec) - tvalBefore.tv_usec);
    // printf("%s: Read Exec Time in microseconds: %ld microseconds \n", __FUNCTION__, exec_time);    
    // if (ret != SGX_SUCCESS) 
    // {
    //   std::cerr << "Error: Making an ecall_execute_sql()" << std::endl;
    // }
   const char *azSql2 = 
                          "BEGIN;"
                          "INSERT INTO t1 VALUES(randomblob(100));"
                          "INSERT INTO t1 VALUES(randomblob(100));"
                          "INSERT INTO t1 SELECT md5sum(x) FROM t1;"
                          "COMMIT;";
     /* Write */
    // gettimeofday (&tvalBefore, NULL);
    ret = ecall_terminus_execute_sql(*(int*)enclave_id, tid, azSql2);
    // gettimeofday (&tvalAfter, NULL);
    // exec_time = (((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000 + tvalAfter.tv_usec) - tvalBefore.tv_usec);
    // printf("%s: Write Exec Time in microseconds: %ld microseconds \n", __FUNCTION__, exec_time);    
    if (ret != SGX_SUCCESS) 
    {
      std::cerr << "Error: Making an ecall_execute_sql()" << std::endl;
    }
    nIter++;
  }
  printf("[%ld] === Thread END === \n", tid);
}
// Application entry
int main(int argc, char *argv[]) {
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls
  int updated = 0;
  int debug_flag = 1;
  long tid = syscall(__NR_gettid); 
  pthread_t threads[NUM_THREADS];
  int status = 0;
  unsigned int eid = 0;
  unsigned long exec_time = 0;

  for(unsigned int i = 0; i < NUM_ENCLAVES; i++)
  {
    per_enclave_meta *encl_meta     = (per_enclave_meta*) malloc(sizeof(per_enclave_meta));
    memset(encl_meta, 0, sizeof(per_enclave_meta));

    encl_meta->sealed_heap_storage  = (uint8_t*) malloc(HS_STORAGE_SIZE);
    encl_meta->sealed_meta_storage  = (uint8_t*) malloc(META_STORAGE_SIZE);
    encl_meta->sealed_return_stack_storage  = (uint8_t*) malloc(RS_STORAGE_SIZE);
    encl_meta->sealed_ssas_storage  = (uint8_t*) malloc(SSA_STORAGE_SIZE);
    encl_meta->thread_info  = (encl_thr_info*) malloc(sizeof(encl_thr_info));

    encl_meta->cfi_key  = (uint8_t*) malloc(16);
    memcpy(encl_meta->cfi_key, cfi_key, 16);
    memset(encl_meta->thread_info, 0, sizeof(encl_thr_info));
    encl_arr[i] = encl_meta;

    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &encl_arr[i]->eid, NULL);
    printf("i = %d, encl_arr[%d]->eid = %d\n", i,i, encl_arr[i]->eid);
    if (ret != SGX_SUCCESS) 
    {
        printf("Failed to create enclave\n");
        return -1;
    }
    printf("%s: Agent info is at %p\n", __FUNCTION__, encl_arr[i]->thread_info);
    ecall_init_AGENTS(  encl_arr[i]->eid, &ret, 
                    encl_arr[i]->sealed_heap_storage, 
                    encl_arr[i]->cfi_key, 
                    encl_arr[i]->sealed_meta_storage,
                    encl_arr[i]->thread_info, 
                    encl_arr[i]->sealed_return_stack_storage,
                    encl_arr[i]->sealed_ssas_storage,
                    (uint8_t *)e1);
    eid = encl_arr[i]->eid;
  }



  // Open SQLite database
  ret = ecall_opendb(eid, tid);
  if (ret != SGX_SUCCESS) 
  {
    std::cerr << "Error: Making an ecall_open()" << std::endl;
    return -1;
  }

  // String concate at compile time
  const char* sql1 = 
                      "PRAGMA journal_mode = WAL;"
                      "CREATE TABLE t1(x PRIMARY KEY);"
                      "INSERT INTO t1 VALUES(randomblob(100));"
                      "INSERT INTO t1 VALUES(randomblob(100));"
                      "INSERT INTO t1 SELECT md5sum(x) FROM t1;"
  ;
  // const char* sql2 = "CREATE TABLE t1(x PRIMARY KEY)";
  // const char* sql3 = "INSERT INTO t1 VALUES(randomblob(100))";
  // const char* sql4 = "INSERT INTO t1 VALUES(randomblob(100))";
  // const char* sql5 = "INSERT INTO t1 SELECT md5sum(x) FROM t1";

  ret =  ecall_execute_sql(eid, tid, sql1);

  if (ret != SGX_SUCCESS) 
  {
      std::cerr << "Error: Making an ecall_execute_sql()" << std::endl;
      return -1;
  }

  struct timeval tvalBefore, tvalAfter;
  gettimeofday (&tvalBefore, NULL);

  for(unsigned int t=0; t < NUM_THREADS; t++)
  {
    status = pthread_create(&threads[t], NULL, walthread1_thread, (void *)&eid);
    if (status)
      {
        printf("ERROR; return code from pthread_create() is %d\n", status);
        exit(-1);
      }
  }

  /* Destroy the thread */
  for (int j = 0; j < NUM_THREADS; j++)
  {
      pthread_join(threads[j], NULL);
  }
  gettimeofday (&tvalAfter, NULL);
  exec_time = (((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000 + tvalAfter.tv_usec) - tvalBefore.tv_usec);
  printf("%s: Exec Time in microseconds: %ld microseconds \n", __FUNCTION__, exec_time);    


  std::cout << "Enter SQL statement to execute or 'quit' to exit: " << std::endl;
  std::string input;
  std::cout << "> ";
  while(getline(std::cin, input)) {
    if (input == "quit") {
      break;
    }
    const char* sql = input.c_str();
    ret =  ecall_execute_sql(eid, tid, sql);
    if (ret != SGX_SUCCESS) {
      std::cerr << "Error: Making an ecall_execute_sql()" << std::endl;
      return -1;
    }
    std::cout << "> ";
  }

  // Closing SQLite database inside enclave
  ret =  ecall_closedb(eid, tid);
  if (ret != SGX_SUCCESS) {
    std::cerr << "Error: Making an ecall_closedb()" << std::endl;
    return -1;
  }

  // Destroy the enclave
  sgx_destroy_enclave(eid);
  if (ret != SGX_SUCCESS) {
    std::cerr << "Error: destroying enclave" << std::endl;
    return -1;
  }

  std::cout << "Info: SQLite SGX enclave successfully returned." << std::endl;
  return 0;
}
