#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

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

#ifndef WRAPPER_INIT_ENCLAVE_DEFINED__
#define WRAPPER_INIT_ENCLAVE_DEFINED__
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, wrapper_init_enclave, (void));
#endif
#ifndef WRAPPER_PRINT_KEY_DEFINED__
#define WRAPPER_PRINT_KEY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, wrapper_print_key, (sgx_enclave_id_t eid));
#endif
#ifndef WRAPPER_SET_KEY_DEFINED__
#define WRAPPER_SET_KEY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, wrapper_set_key, (sgx_enclave_id_t eid, unsigned int a));
#endif
#ifndef WRAPPER_KEYGEN_DEFINED__
#define WRAPPER_KEYGEN_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, wrapper_keygen, (sgx_enclave_id_t eid));
#endif
#ifndef WRAPPER_GET_KEY_DEFINED__
#define WRAPPER_GET_KEY_DEFINED__
unsigned int SGX_UBRIDGE(SGX_NOCONVENTION, wrapper_get_key, (sgx_enclave_id_t eid, unsigned int key));
#endif
#ifndef PRINT_DATA_DEFINED__
#define PRINT_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_data, (unsigned int got));
#endif
#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (char* value));
#endif

sgx_status_t print_key(sgx_enclave_id_t eid);
sgx_status_t set_key(sgx_enclave_id_t eid, unsigned int a);
sgx_status_t keygen(sgx_enclave_id_t eid);
sgx_status_t get_key(sgx_enclave_id_t eid, unsigned int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
