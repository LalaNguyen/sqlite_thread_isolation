#ifndef USEFULMACROS
#define USEFULMACROS

//****************************************************************************/
// MPC-project FS2016
// Purpose: AES128 encryption / decryption
// File:    aes128.h
// Author:  C-Code by Kristian, Laurent Haan,
//          www.codeplanet.eu/tutorials/cpp/51-advanced-encryption
// Author:  in-line Assembler by M. Thaler, ZHAW, 2/2016
//****************************************************************************/

#include <stdint.h>
#define KEYLEN 16 //16 bytes
#define XOR(SRC, DST)\
  __asm__ __volatile__("movaps (%0), %%xmm1   ;\n" \
                   "movaps (%1), %%xmm2   ;\n" \
                   "pxor %%xmm1, %%xmm2   ;\n" \
                   "movdqu %%xmm2, (%1)"::"r"(SRC),"r"(DST));
//----------------------------------------------------------------------------
// Shay Gueron, Intel White Paper: Advanced Encryption Standard
// Key Expansion 128-Bit

#define expandKey() \
    __asm__ __volatile__ ("   movaps          %%xmm5, %%xmm0         ;" \
                          "   pxor            %%xmm2, %%xmm2         ;" \
                          "   aeskeygenassist $1, %%xmm0, %%xmm1     ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm6         ;" \
                          "   aeskeygenassist $2, %%xmm0, %%xmm1     ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm7        ;" \
                          "   aeskeygenassist $4, %%xmm0, %%xmm1     ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm8         ;" \
                          "   aeskeygenassist $8, %%xmm0, %%xmm1     ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm9         ;" \
                          "   aeskeygenassist $16, %%xmm0, %%xmm1    ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm10         ;" \
                          "   aeskeygenassist $32, %%xmm0, %%xmm1    ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm11         ;" \
                          "   aeskeygenassist $64, %%xmm0, %%xmm1    ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm12        ;" \
                          "   aeskeygenassist $0x80, %%xmm0, %%xmm1  ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm13        ;" \
                          "   aeskeygenassist $0x1b, %%xmm0, %%xmm1  ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm14        ;" \
                          "   aeskeygenassist $0x36, %%xmm0, %%xmm1  ;" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm15        ;" \
                            :                                           \
                            :                                           \
                            : );

#define expandKeyInv() \
    __asm__ __volatile__ ("   movaps          %%xmm5, %%xmm0           ;\n" \
                          "   pxor            %%xmm2, %%xmm2           ;\n" \
                          "   aeskeygenassist $1, %%xmm0, %%xmm1       ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm6           ;\n" \
                          "   aeskeygenassist $2, %%xmm0, %%xmm1       ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm7           ;\n" \
                          "   aeskeygenassist $4, %%xmm0, %%xmm1       ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm8           ;\n" \
                          "   aeskeygenassist $8, %%xmm0, %%xmm1       ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm9           ;\n" \
                          "   aeskeygenassist $16, %%xmm0, %%xmm1      ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm10          ;\n" \
                          "   aeskeygenassist $32, %%xmm0, %%xmm1      ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm11          ;\n" \
                          "   aeskeygenassist $64, %%xmm0, %%xmm1    ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm12        ;\n" \
                          "   aeskeygenassist $0x80, %%xmm0, %%xmm1  ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm13        ;\n" \
                          "   aeskeygenassist $0x1b, %%xmm0, %%xmm1  ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   aesimc          %%xmm0, %%xmm14        ;\n" \
                          "   aeskeygenassist $0x36, %%xmm0, %%xmm1  ;\n" \
                          "   pshufd      $0b11111111, %%xmm1, %%xmm1  ;" \
                          "   shufps      $0b00010000, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   shufps      $0b10001100, %%xmm0, %%xmm2  ;" \
                          "   pxor        %%xmm2, %%xmm0               ;" \
                          "   pxor        %%xmm1, %%xmm0               ;" \
                          "   movaps          %%xmm0, %%xmm15        ;\n" \
                            :                                             \
                            :                                             \
                            : );
#define encryptAES128(STATE, CIPHER)                                       \
    __asm__ __volatile__ ("     mov           %0,      %%r10          ;\n" \
                          "     movups        (%%r10), %%xmm0         ;\n" \
                          "     pxor          %%xmm5, %%xmm0          ;\n" \
                          "     aesenc        %%xmm6, %%xmm0          ;\n" \
                          "     aesenc        %%xmm7, %%xmm0          ;\n" \
                          "     aesenc        %%xmm8, %%xmm0          ;\n" \
                          "     aesenc        %%xmm9, %%xmm0          ;\n" \
                          "     aesenc        %%xmm10, %%xmm0         ;\n" \
                          "     aesenc        %%xmm11, %%xmm0         ;\n" \
                          "     aesenc        %%xmm12, %%xmm0         ;\n" \
                          "     aesenc        %%xmm13, %%xmm0         ;\n" \
                          "     aesenc        %%xmm14, %%xmm0         ;\n" \
                          "     aesenclast    %%xmm15, %%xmm0         ;\n" \
                          "     movdqu        %%xmm0, (%1)            ;\n" \
                            :                                              \
                            : "r"(STATE),  "r"(CIPHER)                     \
                            : "%r10");

#define decryptAES128(CIPHER, DATA)                                        \
    __asm__ __volatile__ ("     mov           %0,      %%r10          ;\n" \
                          "     movups        (%%r10), %%xmm0         ;\n" \
                          "     pxor          %%xmm15, %%xmm0         ;\n" \
                          "     aesdec        %%xmm14, %%xmm0         ;\n" \
                          "     aesdec        %%xmm13, %%xmm0         ;\n" \
                          "     aesdec        %%xmm12, %%xmm0         ;\n" \
                          "     aesdec        %%xmm11, %%xmm0         ;\n" \
                          "     aesdec        %%xmm10, %%xmm0         ;\n" \
                          "     aesdec        %%xmm9, %%xmm0          ;\n" \
                          "     aesdec        %%xmm8, %%xmm0          ;\n" \
                          "     aesdec        %%xmm7, %%xmm0          ;\n" \
                          "     aesdec        %%xmm6, %%xmm0          ;\n" \
                          "     aesdeclast    %%xmm5, %%xmm0          ;\n" \
                          "     movdqu        %%xmm0, (%1)            ;\n" \
                            :                                              \
                            : "r"(CIPHER), "r"(DATA)                       \
                            : "%r10");
// assumes input, output and key to be 16 bytes long

// void expandKey(const uint8_t* expandedKey);
// void encryptAES128(const uint8_t* state, const uint8_t *expandedKey, uint8_t cipher[]);
// void decryptAES128(const uint8_t* cipher, const uint8_t *expandedKey, uint8_t dec_data[]);
// void expandKeyInv(const uint8_t *expandedKey);


// void encryptCBC128( uint8_t* state, int dlen, uint8_t *iv, uint8_t cipher[]);
// void decryptCBC128( uint8_t* cipher, int dlen, uint8_t *iv, uint8_t dec_data[]);

#endif
