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

#ifndef PRINT_DATA_DEFINED__
#define PRINT_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, print_data, (unsigned int got));
#endif
#ifndef OCALL_PRINT_DEFINED__
#define OCALL_PRINT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print, (char* value));
#endif

sgx_status_t print_secret(sgx_enclave_id_t eid);
sgx_status_t set_secret(sgx_enclave_id_t eid, unsigned int a);
sgx_status_t addition(sgx_enclave_id_t eid, unsigned int a, unsigned int b);
sgx_status_t get_secret(sgx_enclave_id_t eid, unsigned int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
