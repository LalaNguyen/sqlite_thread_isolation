/*
 *  This file is part of the SGX-Step enclave execution control framework.
 *
 *  Copyright (C) 2017 Jo Van Bulck <jo.vanbulck@cs.kuleuven.be>,
 *                     Raoul Strackx <raoul.strackx@cs.kuleuven.be>
 *
 *  SGX-Step is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  SGX-Step is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with SGX-Step. If not, see <http://www.gnu.org/licenses/>.
 */

/* 32-bit compatibility ~~following Intel SGX-SDK convention. */
#if defined(M32)
    #define xax  eax
    #define xbx  ebx
    #define xcx  ecx
    #define xdi  edi
    #define movx movl
#else
    #define xax  rax
    #define xbx  rbx
    #define xcx  rcx
    #define xdi  rdi
    #define movx movq
#endif

/* load the address of `symbol' to the register `reg' in PIC way. */
.macro lea_pic symbol, reg
    lea   \symbol(%rip), \reg
.endm
/* 
 * ---------------------------------------------------------------------
 * Function: sgx_aep_trampoline
 *      Code that will be returned to after interrupting an enclave.
 *
 * Registers:
 *      XAX - ERESUME leaf
 *      XBX - TSC address
 *      XCX - AEP address
 */
.data
g_aep_cb:
    .word 0x0
    .word 0x0
    .word 0x0
    .word 0x0

.text
    .global sgx_aep_trampoline
    .type sgx_aep_trampoline, @function
sgx_aep_trampoline:
    // mov %xbx, sgx_step_tcs(%rip)
    /* optional C function callback */
    lea_pic     g_aep_cb, %xax
    call *(%xax)

.Leresume:
    mov $3, %xax                                /* ERESUME leaf */
    enclu                                       /* ENCLU */


    .global sgx_default_aep_trampoline
    .type sgx_default_aep_trampoline, @function
sgx_default_aep_trampoline:
    enclu


    .global set_callback
    .type set_callback, @function
set_callback:
    lea_pic     g_aep_cb, %xax
    mov         %rdi,   %xbx
    mov         %xbx, (%xax)
    ret
 