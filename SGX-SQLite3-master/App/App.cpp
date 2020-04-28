#include "sgx_urts.h"
#include "Enclave_u.h"
#include <iostream>
#include <string>
#include <pthread.h>
# include <unistd.h>
#define __NR_gettid 186
# define MAX_PATH FILENAME_MAX
# define ENCLAVE_FILENAME "enclave.signed.so"
#define NUM_THREADS 5
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

void *walthread1_thread(void *enclave_id)
{
  int nIter = 0;
  long tid = syscall(__NR_gettid); 
  printf("[%ld] === Thread BEGIN === \n", tid);
  sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls
  const char *azSql[] = {
      "SELECT md5sum(x) FROM t1 WHERE rowid != (SELECT max(rowid) FROM t1)",
    };
  while(nIter <= 3)
  {
    ret = ecall_execute_sql(*(int*)enclave_id, azSql[0]);
    if (ret != SGX_SUCCESS) 
    {
      std::cerr << "Error: Making an ecall_execute_sql()" << std::endl;
    }
   const char *azSql2 = 
                          "BEGIN;"
                          "INSERT INTO t1 VALUES(randomblob(100));"
                          "INSERT INTO t1 VALUES(randomblob(100));"
                          "INSERT INTO t1 SELECT md5sum(x) FROM t1;"
                          "COMMIT;";
    ret = ecall_execute_sql(*(int*)enclave_id, azSql2);
    if (ret != SGX_SUCCESS) 
    {
      std::cerr << "Error: Making an ecall_execute_sql()" << std::endl;
    }
    nIter++;
  }
}
// Application entry
int main(int argc, char *argv[]) {
  sgx_enclave_id_t eid = 0;
  char token_path[MAX_PATH] = {'\0'};
  sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED; // status flag for enclave calls
  int updated = 0;
  int debug_flag = 1;
  pthread_t threads[NUM_THREADS];
  int status = 0;
  // Initialize the enclave
  ret = sgx_create_enclave(ENCLAVE_FILENAME, debug_flag, &token, &updated, &eid, NULL);
  if (ret != SGX_SUCCESS) 
  {
    std::cerr << "Error: creating enclave" << std::endl;
    return -1;
  }
  std::cout << "Info: SQLite SGX enclave successfully created." << std::endl;


  // Open SQLite database
  ret = ecall_opendb(eid);
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

  ret =  ecall_execute_sql(eid, sql1);

  if (ret != SGX_SUCCESS) 
  {
      std::cerr << "Error: Making an ecall_execute_sql()" << std::endl;
      return -1;
  }

  for(unsigned int t=0; t < NUM_THREADS; t++)
  {
    printf("In main: creating thread %ld\n", t);
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


  std::cout << "Enter SQL statement to execute or 'quit' to exit: " << std::endl;
  std::string input;
  std::cout << "> ";
  while(getline(std::cin, input)) {
    if (input == "quit") {
      break;
    }
    const char* sql = input.c_str();
    ret =  ecall_execute_sql(eid, sql);
    if (ret != SGX_SUCCESS) {
      std::cerr << "Error: Making an ecall_execute_sql()" << std::endl;
      return -1;
    }
    std::cout << "> ";
  }

  // Closing SQLite database inside enclave
  ret =  ecall_closedb(eid);
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
