#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void print_key(void);
void set_key(unsigned int a);
void keygen(void);
unsigned int get_key(void);

sgx_status_t SGX_CDECL wrapper_init_enclave(unsigned int* retval);
sgx_status_t SGX_CDECL wrapper_print_key(sgx_enclave_id_t eid);
sgx_status_t SGX_CDECL wrapper_set_key(sgx_enclave_id_t eid, unsigned int a);
sgx_status_t SGX_CDECL wrapper_keygen(sgx_enclave_id_t eid);
sgx_status_t SGX_CDECL wrapper_get_key(unsigned int* retval, sgx_enclave_id_t eid, unsigned int key);
sgx_status_t SGX_CDECL print_data(unsigned int got);
sgx_status_t SGX_CDECL ocall_print(char* value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
