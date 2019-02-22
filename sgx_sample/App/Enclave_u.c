#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_set_secret_t {
	unsigned int ms_a;
} ms_set_secret_t;

typedef struct ms_addition_t {
	unsigned int ms_a;
	unsigned int ms_b;
} ms_addition_t;

typedef struct ms_get_secret_t {
	unsigned int ms_retval;
} ms_get_secret_t;

typedef struct ms_print_data_t {
	unsigned int ms_got;
} ms_print_data_t;

typedef struct ms_ocall_print_t {
	char* ms_value;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave_print_data(void* pms)
{
	ms_print_data_t* ms = SGX_CAST(ms_print_data_t*, pms);
	print_data(ms->ms_got);

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
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_print_data,
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t print_secret(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t set_secret(sgx_enclave_id_t eid, unsigned int a)
{
	sgx_status_t status;
	ms_set_secret_t ms;
	ms.ms_a = a;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t addition(sgx_enclave_id_t eid, unsigned int a, unsigned int b)
{
	sgx_status_t status;
	ms_addition_t ms;
	ms.ms_a = a;
	ms.ms_b = b;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t get_secret(sgx_enclave_id_t eid, unsigned int* retval)
{
	sgx_status_t status;
	ms_get_secret_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

