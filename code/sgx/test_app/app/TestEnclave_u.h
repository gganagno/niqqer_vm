#ifndef TESTENCLAVE_U_H__
#define TESTENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef UPRINT_DEFINED__
#define UPRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, uprint, (const char* str));
#endif
#ifndef USGX_EXIT_DEFINED__
#define USGX_EXIT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, usgx_exit, (int reason));
#endif
#ifndef PRINT_RSA_KEY_DEFINED__
#define PRINT_RSA_KEY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_rsa_key, (uint8_t* r));
#endif
#ifndef PRINT_DATA_DEFINED__
#define PRINT_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_data, (char* got, int len));
#endif
#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (char* value));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t generate_keypair(sgx_enclave_id_t eid, int* retval, int size);
sgx_status_t aes_getbytes(sgx_enclave_id_t eid, int* retval, int id);
sgx_status_t print_key(sgx_enclave_id_t eid, int id);
sgx_status_t keygen(sgx_enclave_id_t eid, int* retval, int size);
sgx_status_t get_key(sgx_enclave_id_t eid, int id, char* got, int size);
sgx_status_t get_pubkey(sgx_enclave_id_t eid, int id, char* r);
sgx_status_t get_privkey(sgx_enclave_id_t eid, int id, char* r);
sgx_status_t rsa_encrypt(sgx_enclave_id_t eid, int id, unsigned char* msg, unsigned char* r);
sgx_status_t rsa_decrypt(sgx_enclave_id_t eid, int id, unsigned char* msg, unsigned char* r);
sgx_status_t rsa_get_key_size(sgx_enclave_id_t eid, int* retval, int id);
sgx_status_t aes_encrypt(sgx_enclave_id_t eid, int id, unsigned char* msg, int len, unsigned char* result);
sgx_status_t aes_decrypt(sgx_enclave_id_t eid, int id, unsigned char* msg, int len, unsigned char* result);
sgx_status_t startup(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
