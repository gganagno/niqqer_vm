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

void print_key(int id);
int keygen(int size);
void get_key(int id, char* got, int size);
int Test(sgx_status_t* error);

sgx_status_t SGX_CDECL print_rsa_key(uint8_t* r);
sgx_status_t SGX_CDECL print_data(char* got, int len);
sgx_status_t SGX_CDECL ocall_print(char* value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
