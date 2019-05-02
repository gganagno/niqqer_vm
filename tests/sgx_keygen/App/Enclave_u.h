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

sgx_status_t print_key(sgx_enclave_id_t eid, int id);
sgx_status_t keygen(sgx_enclave_id_t eid, int* retval, int size);
sgx_status_t get_key(sgx_enclave_id_t eid, int id, char* got, int size);
sgx_status_t Test(sgx_enclave_id_t eid, int* retval, sgx_status_t* error);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
