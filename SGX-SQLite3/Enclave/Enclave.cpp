#include "Enclave_t.h"
#include "sqlite3.h"
#include <string>
#include <stdio.h> /* vsnprintf */
#include <stdarg.h>
#include "md5.h"
#include "sgx_thread.h"

static sgx_thread_mutex_t global_mutex = SGX_THREAD_MUTEX_INITIALIZER;
static sqlite3* db;  // Database connection object

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

//SQLite callback function for printing results
static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
  int i;
  for(i = 0; i < 1; i++){
    std::string azColName_str = azColName[i];
    std::string argv_str = (argv[i] ? argv[i] : "NULL");
    printf((azColName_str + " = " + argv_str + "\n").c_str());
  }
  printf("\n");
  return 0;
}

void ecall_opendb(long tid) 
{
  int rc = sqlite3_open(":memory:", &db);  // Opening In-Memory database
  uint8_t * lks_buffer = (uint8_t*) malloc(500*100); // size = 100 bytes * cnt = 500 slots
  /* Register the our lookaside buffer memory */  
  sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, lks_buffer, 100, 500);

  if (rc) {
    ocall_println_string("[SQLite3 Error] - can't open database connection: ");
    ocall_println_string(sqlite3_errmsg(db));
    return;
  }
  sqlite3_create_function(db, "md5sum", -1, SQLITE_UTF8, 0, 0, md5step, md5finalize);
  sqlite3_exec(db, "PRAGMA synchronous=OFF", 0, 0, 0);
}

void ecall_execute_sql(long tid, const char *sql) {
  int rc;
  char *zErrMsg = NULL;
  sgx_thread_mutex_lock(&global_mutex);
  rc = sqlite3_exec(db, sql, 0, 0, &zErrMsg);
  sgx_thread_mutex_unlock(&global_mutex);
}

void ecall_closedb(long tid) {
  sqlite3_close(db);
  ocall_println_string("[SQLite3 Info] - Closed database connection");
}
