#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_print_key_t {
	int ms_id;
} ms_print_key_t;

typedef struct ms_keygen_t {
	int ms_retval;
	int ms_size;
} ms_keygen_t;

typedef struct ms_get_key_t {
	int ms_id;
	char* ms_got;
	int ms_size;
} ms_get_key_t;

typedef struct ms_Test_t {
	int ms_retval;
	sgx_status_t* ms_error;
} ms_Test_t;

typedef struct ms_print_rsa_key_t {
	uint8_t* ms_r;
} ms_print_rsa_key_t;

typedef struct ms_print_data_t {
	char* ms_got;
	int ms_len;
} ms_print_data_t;

typedef struct ms_ocall_print_t {
	char* ms_value;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave_print_rsa_key(void* pms)
{
	ms_print_rsa_key_t* ms = SGX_CAST(ms_print_rsa_key_t*, pms);
	print_rsa_key(ms->ms_r);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_print_data(void* pms)
{
	ms_print_data_t* ms = SGX_CAST(ms_print_data_t*, pms);
	print_data(ms->ms_got, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_value);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[3];
} ocall_table_Enclave = {
	3,
	{
		(void*)Enclave_print_rsa_key,
		(void*)Enclave_print_data,
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t print_key(sgx_enclave_id_t eid, int id)
{
	sgx_status_t status;
	ms_print_key_t ms;
	ms.ms_id = id;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t keygen(sgx_enclave_id_t eid, int* retval, int size)
{
	sgx_status_t status;
	ms_keygen_t ms;
	ms.ms_size = size;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_key(sgx_enclave_id_t eid, int id, char* got, int size)
{
	sgx_status_t status;
	ms_get_key_t ms;
	ms.ms_id = id;
	ms.ms_got = got;
	ms.ms_size = size;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t Test(sgx_enclave_id_t eid, int* retval, sgx_status_t* error)
{
	sgx_status_t status;
	ms_Test_t ms;
	ms.ms_error = error;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

