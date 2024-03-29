#ifndef TESTENCLAVE_T_H__
#define TESTENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int generate_keypair(int size);
int aes_getbytes(int id);
void print_key(int id);
int keygen(int size);
void get_key(int id, char* got, int size);
void get_pubkey(int id, char* r);
void get_privkey(int id, char* r);
void rsa_encrypt(int id, unsigned char* msg, unsigned char* r);
void rsa_decrypt(int id, unsigned char* msg, unsigned char* r);
int rsa_get_key_size(int id);
void aes_encrypt(int id, unsigned char* msg, int len, unsigned char* result);
void aes_decrypt(int id, unsigned char* msg, int len, unsigned char* result);
void startup(void);

sgx_status_t SGX_CDECL uprint(const char* str);
sgx_status_t SGX_CDECL usgx_exit(int reason);
sgx_status_t SGX_CDECL print_rsa_key(uint8_t* r);
sgx_status_t SGX_CDECL print_data(char* got, int len);
sgx_status_t SGX_CDECL ocall_print(char* value);
sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
