#include "Enclave_t.h"
#include <string>
#include <stdio.h> /* vsnprintf */
#include <stdarg.h>
#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "sgx_trts_exception.h"
#include "agent_meta.h"
#include "sqlite3.h"

static enclave_thread_dbg *e1 = ( enclave_thread_dbg *)malloc(sizeof(enclave_thread_dbg));
static void * g_lks_buffer = NULL;

#ifndef uint32
#  define uint32 unsigned int
#endif
struct MD5Context {
  int isInit;
  uint32 buf[4];
  uint32 bits[2];
  union {
    unsigned char in[64];
    uint32 in32[16];
  } u;
};
typedef struct MD5Context MD5Context;

/*
 * Note: this code is harmless on little-endian machines.
 */
static void byteReverse (unsigned char *buf, unsigned longs){
  uint32 t;
  do {
    t = (uint32)((unsigned)buf[3]<<8 | buf[2]) << 16 |
          ((unsigned)buf[1]<<8 | buf[0]);
    *(uint32 *)buf = t;
    buf += 4;
  } while (--longs);
}
/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
  ( w += f(x, y, z) + data,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
static void MD5Transform(uint32 buf[4], const uint32 in[16]){
  register uint32 a, b, c, d;

  a = buf[0];
  b = buf[1];
  c = buf[2];
  d = buf[3];

  MD5STEP(F1, a, b, c, d, in[ 0]+0xd76aa478,  7);
  MD5STEP(F1, d, a, b, c, in[ 1]+0xe8c7b756, 12);
  MD5STEP(F1, c, d, a, b, in[ 2]+0x242070db, 17);
  MD5STEP(F1, b, c, d, a, in[ 3]+0xc1bdceee, 22);
  MD5STEP(F1, a, b, c, d, in[ 4]+0xf57c0faf,  7);
  MD5STEP(F1, d, a, b, c, in[ 5]+0x4787c62a, 12);
  MD5STEP(F1, c, d, a, b, in[ 6]+0xa8304613, 17);
  MD5STEP(F1, b, c, d, a, in[ 7]+0xfd469501, 22);
  MD5STEP(F1, a, b, c, d, in[ 8]+0x698098d8,  7);
  MD5STEP(F1, d, a, b, c, in[ 9]+0x8b44f7af, 12);
  MD5STEP(F1, c, d, a, b, in[10]+0xffff5bb1, 17);
  MD5STEP(F1, b, c, d, a, in[11]+0x895cd7be, 22);
  MD5STEP(F1, a, b, c, d, in[12]+0x6b901122,  7);
  MD5STEP(F1, d, a, b, c, in[13]+0xfd987193, 12);
  MD5STEP(F1, c, d, a, b, in[14]+0xa679438e, 17);
  MD5STEP(F1, b, c, d, a, in[15]+0x49b40821, 22);

  MD5STEP(F2, a, b, c, d, in[ 1]+0xf61e2562,  5);
  MD5STEP(F2, d, a, b, c, in[ 6]+0xc040b340,  9);
  MD5STEP(F2, c, d, a, b, in[11]+0x265e5a51, 14);
  MD5STEP(F2, b, c, d, a, in[ 0]+0xe9b6c7aa, 20);
  MD5STEP(F2, a, b, c, d, in[ 5]+0xd62f105d,  5);
  MD5STEP(F2, d, a, b, c, in[10]+0x02441453,  9);
  MD5STEP(F2, c, d, a, b, in[15]+0xd8a1e681, 14);
  MD5STEP(F2, b, c, d, a, in[ 4]+0xe7d3fbc8, 20);
  MD5STEP(F2, a, b, c, d, in[ 9]+0x21e1cde6,  5);
  MD5STEP(F2, d, a, b, c, in[14]+0xc33707d6,  9);
  MD5STEP(F2, c, d, a, b, in[ 3]+0xf4d50d87, 14);
  MD5STEP(F2, b, c, d, a, in[ 8]+0x455a14ed, 20);
  MD5STEP(F2, a, b, c, d, in[13]+0xa9e3e905,  5);
  MD5STEP(F2, d, a, b, c, in[ 2]+0xfcefa3f8,  9);
  MD5STEP(F2, c, d, a, b, in[ 7]+0x676f02d9, 14);
  MD5STEP(F2, b, c, d, a, in[12]+0x8d2a4c8a, 20);

  MD5STEP(F3, a, b, c, d, in[ 5]+0xfffa3942,  4);
  MD5STEP(F3, d, a, b, c, in[ 8]+0x8771f681, 11);
  MD5STEP(F3, c, d, a, b, in[11]+0x6d9d6122, 16);
  MD5STEP(F3, b, c, d, a, in[14]+0xfde5380c, 23);
  MD5STEP(F3, a, b, c, d, in[ 1]+0xa4beea44,  4);
  MD5STEP(F3, d, a, b, c, in[ 4]+0x4bdecfa9, 11);
  MD5STEP(F3, c, d, a, b, in[ 7]+0xf6bb4b60, 16);
  MD5STEP(F3, b, c, d, a, in[10]+0xbebfbc70, 23);
  MD5STEP(F3, a, b, c, d, in[13]+0x289b7ec6,  4);
  MD5STEP(F3, d, a, b, c, in[ 0]+0xeaa127fa, 11);
  MD5STEP(F3, c, d, a, b, in[ 3]+0xd4ef3085, 16);
  MD5STEP(F3, b, c, d, a, in[ 6]+0x04881d05, 23);
  MD5STEP(F3, a, b, c, d, in[ 9]+0xd9d4d039,  4);
  MD5STEP(F3, d, a, b, c, in[12]+0xe6db99e5, 11);
  MD5STEP(F3, c, d, a, b, in[15]+0x1fa27cf8, 16);
  MD5STEP(F3, b, c, d, a, in[ 2]+0xc4ac5665, 23);

  MD5STEP(F4, a, b, c, d, in[ 0]+0xf4292244,  6);
  MD5STEP(F4, d, a, b, c, in[ 7]+0x432aff97, 10);
  MD5STEP(F4, c, d, a, b, in[14]+0xab9423a7, 15);
  MD5STEP(F4, b, c, d, a, in[ 5]+0xfc93a039, 21);
  MD5STEP(F4, a, b, c, d, in[12]+0x655b59c3,  6);
  MD5STEP(F4, d, a, b, c, in[ 3]+0x8f0ccc92, 10);
  MD5STEP(F4, c, d, a, b, in[10]+0xffeff47d, 15);
  MD5STEP(F4, b, c, d, a, in[ 1]+0x85845dd1, 21);
  MD5STEP(F4, a, b, c, d, in[ 8]+0x6fa87e4f,  6);
  MD5STEP(F4, d, a, b, c, in[15]+0xfe2ce6e0, 10);
  MD5STEP(F4, c, d, a, b, in[ 6]+0xa3014314, 15);
  MD5STEP(F4, b, c, d, a, in[13]+0x4e0811a1, 21);
  MD5STEP(F4, a, b, c, d, in[ 4]+0xf7537e82,  6);
  MD5STEP(F4, d, a, b, c, in[11]+0xbd3af235, 10);
  MD5STEP(F4, c, d, a, b, in[ 2]+0x2ad7d2bb, 15);
  MD5STEP(F4, b, c, d, a, in[ 9]+0xeb86d391, 21);

  buf[0] += a;
  buf[1] += b;
  buf[2] += c;
  buf[3] += d;
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
static void MD5Init(MD5Context *ctx){
  ctx->isInit = 1;
  ctx->buf[0] = 0x67452301;
  ctx->buf[1] = 0xefcdab89;
  ctx->buf[2] = 0x98badcfe;
  ctx->buf[3] = 0x10325476;
  ctx->bits[0] = 0;
  ctx->bits[1] = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
static 
void MD5Update(MD5Context *ctx, const unsigned char *buf, unsigned int len){
  uint32 t;

  /* Update bitcount */

  t = ctx->bits[0];
  if ((ctx->bits[0] = t + ((uint32)len << 3)) < t)
    ctx->bits[1]++; /* Carry from low to high */
  ctx->bits[1] += len >> 29;

  t = (t >> 3) & 0x3f;    /* Bytes already in shsInfo->data */

  /* Handle any leading odd-sized chunks */

  if ( t ) {
    unsigned char *p = (unsigned char *)ctx->u.in + t;

    t = 64-t;
    if (len < t) {
      memcpy(p, buf, len);
      return;
    }
    memcpy(p, buf, t);
    byteReverse(ctx->u.in, 16);
    MD5Transform(ctx->buf, (uint32 *)ctx->u.in);
    buf += t;
    len -= t;
  }

  /* Process data in 64-byte chunks */

  while (len >= 64) {
    memcpy(ctx->u.in, buf, 64);
    byteReverse(ctx->u.in, 16);
    MD5Transform(ctx->buf, (uint32 *)ctx->u.in);
    buf += 64;
    len -= 64;
  }

  /* Handle any remaining bytes of data. */

  memcpy(ctx->u.in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern 
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
static void MD5Final(unsigned char digest[16], MD5Context *ctx){
  unsigned count;
  unsigned char *p;

  /* Compute number of bytes mod 64 */
  count = (ctx->bits[0] >> 3) & 0x3F;

  /* Set the first char of padding to 0x80.  This is safe since there is
     always at least one byte free */
  p = ctx->u.in + count;
  *p++ = 0x80;

  /* Bytes of padding needed to make 64 bytes */
  count = 64 - 1 - count;

  /* Pad out to 56 mod 64 */
  if (count < 8) {
    /* Two lots of padding:  Pad the first block to 64 bytes */
    memset(p, 0, count);
    byteReverse(ctx->u.in, 16);
    MD5Transform(ctx->buf, (uint32 *)ctx->u.in);

    /* Now fill the next block with 56 bytes */
    memset(ctx->u.in, 0, 56);
  } else {
    /* Pad block to 56 bytes */
    memset(p, 0, count-8);
  }
  byteReverse(ctx->u.in, 14);

  /* Append length in bits and transform */
  ctx->u.in32[14] = ctx->bits[0];
  ctx->u.in32[15] = ctx->bits[1];

  MD5Transform(ctx->buf, (uint32 *)ctx->u.in);
  byteReverse((unsigned char *)ctx->buf, 4);
  memcpy(digest, ctx->buf, 16);
  memset(ctx, 0, sizeof(*ctx));    /* In case it is sensitive */
}

/*
** Convert a 128-bit MD5 digest into a 32-digit base-16 number.
*/
static void MD5DigestToBase16(unsigned char *digest, char *zBuf){
  static char const zEncode[] = "0123456789abcdef";
  int i, j;

  for(j=i=0; i<16; i++){
    int a = digest[i];
    zBuf[j++] = zEncode[(a>>4)&0xf];
    zBuf[j++] = zEncode[a & 0xf];
  }
  zBuf[j] = 0;
}

/*
** During testing, the special md5sum() aggregate function is available.
** inside SQLite.  The following routines implement that function.
*/
static void md5step(sqlite3_context *context, int argc, sqlite3_value **argv){
  MD5Context *p;
  int i;
  if( argc<1 ) return;
  p = (MD5Context*) sqlite3_aggregate_context(context, sizeof(*p));
  if( p==0 ) return;
  if( !p->isInit ){
    MD5Init(p);
  }
  for(i=0; i<argc; i++){
    const char *zData = (char*)sqlite3_value_text(argv[i]);
    if( zData ){
      MD5Update(p, (unsigned char*)zData, strlen(zData));
    }
  }
}
static void md5finalize(sqlite3_context *context){
  MD5Context *p;
  unsigned char digest[16];
  char zBuf[33];
  p = (MD5Context*) sqlite3_aggregate_context(context, sizeof(*p));
  MD5Final(digest,p);
  MD5DigestToBase16(digest, zBuf);
  sqlite3_result_text(context, zBuf, -1, SQLITE_TRANSIENT);
}

/*
** End of copied md5sum() code.
**************************************************************************/

static sqlite3* db;  // Database connection object

int my_printf(long my_tid, const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_my_print_string(my_tid, buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

//SQLite callback function for printing results
static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
  int i;
  for(i = 0; i < 1; i++){
    std::string azColName_str = azColName[i];
    std::string argv_str = (argv[i] ? argv[i] : "NULL");
    my_printf(0,(azColName_str + " = " + argv_str + "\n").c_str());
  }
  my_printf(0,"\n");
  return 0;
}

static int busyhandler(void *pArg, int n){
  int i = 0;
  while (i<10000)
  {
    i++;
  }
  return 0;
}



sgx_status_t ecall_init_AGENTS(   uint8_t *heap_storage,
                            uint8_t *cfi_key, uint8_t *meta_storage, 
                            void *agent_status, uint8_t *return_stack_storage, 
                            uint8_t *ssas_storage,
                            uint8_t *debug_pointer) 
{
  (void) heap_storage;
  
  uint32_t ret = 0;   
  /* Retrieve enclave info */
  
  if (sgx_is_within_enclave(cfi_key, KEYLEN) != 1)
        abort();

  /* Seal the CFI key*/
  ret = sgx_seal_data(0, NULL, KEYLEN, (uint8_t*)cfi_key, SEALED_CFI_KEY_SIZE, (sgx_sealed_data_t *)sealed_cfi_key); 
  assert(ret == SGX_SUCCESS);

  sgx_register_seal_key(sealed_cfi_key);
  sgx_register_meta_storage(meta_storage);
  sgx_register_agent_status(agent_status);
  sgx_register_return_stack_storage(return_stack_storage);
  sgx_register_ssas_storage(ssas_storage);
  sgx_register_private_data_storage(heap_storage); /* Agent uses heap storage to store sensitive data requested by program */

  agent_info = (encl_thr_info*) agent_status;
  e1 =  (enclave_thread_dbg *) debug_pointer;
  return SGX_SUCCESS;
}


void ecall_opendb(long tid) {
  int rc = sqlite3_open(":memory:", &db);  // Opening In-Memory database
  uint8_t * lks_buffer = (uint8_t*) malloc(500*100); // size = 100 bytes * cnt = 500 slots
  /* Register the our lookaside buffer memory */  
  sqlite3_db_config(db, SQLITE_DBCONFIG_LOOKASIDE, lks_buffer, 100, 500);
  uint8_t *lks_config_p = (uint8_t*) my_get_lookaside(db);
  int size = my_get_lookaside_size();
  sgx_register_private_mem(lks_buffer, 50000, lks_config_p, size);
  g_lks_buffer = lks_buffer;
  if (rc) {
    ocall_println_string("[SQLite3 Error] - can't open database connection: ");
    ocall_println_string(sqlite3_errmsg(db));
    return;
  }
  sqlite3_create_function(db, "md5sum", -1, SQLITE_UTF8, 0, 0, md5step, md5finalize);
  sqlite3_exec(db, "PRAGMA synchronous=OFF", 0, 0, 0);
  sgx_snapshot_private_mem(lks_buffer);
 /* Register the private memory to agent */
}

void ecall_terminus_execute_sql(long tid, const char *sql) {
  int rc;
  char *zErrMsg = NULL;
  // sgx_thread_mutex_lock(&global_mutex);
  // long *a  = (long*) my_sqlite3DbMallocRaw(db, 8);
  // *a = tid;
  rc = sqlite3_exec(db, sql, NULL, 0, &zErrMsg);
  // sgx_thread_mutex_unlock(&global_mutex);
}

void ecall_execute_sql(long tid, const char *sql) {
  int rc;
  char *zErrMsg = NULL;
  // sgx_thread_mutex_lock(&global_mutex);
  rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);
  if (rc) {
    ocall_print_string("[SQLite3 error] - ");
    ocall_println_string(sqlite3_errmsg(db));
    return;
  }
  // sgx_thread_mutex_unlock(&global_mutex);
}

void ecall_closedb(long tid) {
  sqlite3_close(db);
  ocall_println_string("[SQLite3 Info] - Closed database connection");
}
