#include "sqlite3.h"	
#include <stdio.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdlib.h>
#include "md5.h"
#define __NR_gettid 186

#define NUM_THREADS 1


void *walthread1_thread(void *db)
{
  int nIter = 0;
  long tid = syscall(__NR_gettid); 
    char *err_msg = 0;  
  unsigned long exec_time = 0;
  struct timeval tvalBefore, tvalAfter;
  printf("[%ld] === Thread BEGIN === \n", tid);
  int rc = 0; // status flag for enclave calls
  const char *azSql[] = {
      "SELECT md5sum(x) FROM t1 WHERE rowid != (SELECT max(rowid) FROM t1)",
    };
  while(nIter < 10)
  {
    exec_time = 0;
    gettimeofday (&tvalBefore, NULL);
    rc =  sqlite3_exec(db,azSql[0], 0,0,&err_msg);
  gettimeofday (&tvalAfter, NULL);
  exec_time = (((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000 + tvalAfter.tv_usec) - tvalBefore.tv_usec);
  printf("%s: Read Exec Time in microseconds: %ld microseconds \n", __FUNCTION__, exec_time);    

    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    } 
   const char *azSql2 = 
                          "BEGIN;"
                          "INSERT INTO t1 VALUES(randomblob(100));"
                          "INSERT INTO t1 VALUES(randomblob(100));"
                          "INSERT INTO t1 SELECT md5sum(x) FROM t1;"
                          "COMMIT;";
 exec_time = 0;
    gettimeofday (&tvalBefore, NULL);
    rc =  sqlite3_exec(db, azSql2, 0,0,&err_msg);
  gettimeofday (&tvalAfter, NULL);
  exec_time = (((tvalAfter.tv_sec - tvalBefore.tv_sec)*1000000 + tvalAfter.tv_usec) - tvalBefore.tv_usec);
  printf("%s: Write Exec Time in microseconds: %ld microseconds \n", __FUNCTION__, exec_time);    

    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    } 
    nIter++;
  }
  printf("[%ld] === Thread END === \n", tid);
}

//SQLite callback function for printing results
static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
  int i;
  for(i = 0; i < argc; i++){
    char* azColName_str = azColName[i];
    char* argv_str = (argv[i] ? argv[i] : "NULL");
    printf( "%s = %s \n", azColName_str, argv_str);
  }
  printf("\n");
  return 0;
}


// Application entry
int main(int argc, char *argv[]) { 
  pthread_t threads[NUM_THREADS];
  unsigned long exec_time = 0;
  sqlite3 *db;
  char *err_msg = 0;
  struct timeval tvalBefore, tvalAfter;
  unsigned char * lks_buffer;
  printf("%s\n", sqlite3_libversion()); 
  sqlite3_config(SQLITE_CONFIG_SERIALIZED);
  lks_buffer = (unsigned char*) malloc(500*100); // size = 100 bytes * cnt = 500 slots
  /* Register the our lookaside buffer memory */  
  // Open SQLite database
  int rc = sqlite3_open(":memory:", &db);
  
  if (rc != SQLITE_OK) 
{
        
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        
        return 1;
 }
  sqlite3_create_function(db, "md5sum", -1, SQLITE_UTF8, 0, 0, md5step, md5finalize);

  // String concate at compile time
  const char* sql = 
                      "PRAGMA journal_mode = WAL;"
                      "CREATE TABLE t1(x PRIMARY KEY);"
                      "INSERT INTO t1 VALUES(randomblob(100));"
                      "INSERT INTO t1 VALUES(randomblob(100));"
                      "INSERT INTO t1 SELECT md5sum(x) FROM t1;"
  ;
  sqlite3_exec(db, "PRAGMA synchronous=OFF", 0, 0, 0);
  sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, lks_buffer, 100, 500);


  rc =  sqlite3_exec(db,sql, 0,0,&err_msg);

    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    } 


  gettimeofday (&tvalBefore, NULL);

  for(unsigned int t=0; t < NUM_THREADS; t++)
  {
    rc = pthread_create(&threads[t], NULL, walthread1_thread, (void *)db);
    if (rc)
      {
        printf("ERROR; return code from pthread_create() is %d\n", rc);
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

  const char *azSql2 = "SELECT COUNT(x) FROM t1"
                         ;
    rc =  sqlite3_exec(db, azSql2, callback,0,&err_msg);
    if (rc != SQLITE_OK ) {
        
        fprintf(stderr, "SQL error: %s\n", err_msg);
        
        sqlite3_free(err_msg);        
        sqlite3_close(db);
        
        return 1;
    } 

  return 0;
}

