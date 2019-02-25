#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_set_key_t {
	unsigned int ms_a;
} ms_set_key_t;

typedef struct ms_get_key_t {
	unsigned int ms_retval;
} ms_get_key_t;

typedef struct ms_wrapper_init_enclave_t {
	unsigned int ms_retval;
} ms_wrapper_init_enclave_t;

typedef struct ms_wrapper_print_key_t {
	sgx_enclave_id_t ms_eid;
} ms_wrapper_print_key_t;

typedef struct ms_wrapper_set_key_t {
	sgx_enclave_id_t ms_eid;
	unsigned int ms_a;
} ms_wrapper_set_key_t;

typedef struct ms_wrapper_keygen_t {
	sgx_enclave_id_t ms_eid;
} ms_wrapper_keygen_t;

typedef struct ms_wrapper_get_key_t {
	unsigned int ms_retval;
	sgx_enclave_id_t ms_eid;
	unsigned int ms_key;
} ms_wrapper_get_key_t;

typedef struct ms_print_data_t {
	unsigned int ms_got;
} ms_print_data_t;

typedef struct ms_ocall_print_t {
	char* ms_value;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL Enclave_wrapper_init_enclave(void* pms)
{
	ms_wrapper_init_enclave_t* ms = SGX_CAST(ms_wrapper_init_enclave_t*, pms);
	ms->ms_retval = wrapper_init_enclave();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrapper_print_key(void* pms)
{
	ms_wrapper_print_key_t* ms = SGX_CAST(ms_wrapper_print_key_t*, pms);
	wrapper_print_key(ms->ms_eid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrapper_set_key(void* pms)
{
	ms_wrapper_set_key_t* ms = SGX_CAST(ms_wrapper_set_key_t*, pms);
	wrapper_set_key(ms->ms_eid, ms->ms_a);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrapper_keygen(void* pms)
{
	ms_wrapper_keygen_t* ms = SGX_CAST(ms_wrapper_keygen_t*, pms);
	wrapper_keygen(ms->ms_eid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrapper_get_key(void* pms)
{
	ms_wrapper_get_key_t* ms = SGX_CAST(ms_wrapper_get_key_t*, pms);
	ms->ms_retval = wrapper_get_key(ms->ms_eid, ms->ms_key);

	return SGX_SUCCESS;
}

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
	void * table[7];
} ocall_table_Enclave = {
	7,
	{
		(void*)Enclave_wrapper_init_enclave,
		(void*)Enclave_wrapper_print_key,
		(void*)Enclave_wrapper_set_key,
		(void*)Enclave_wrapper_keygen,
		(void*)Enclave_wrapper_get_key,
		(void*)Enclave_print_data,
		(void*)Enclave_ocall_print,
	}
};
sgx_status_t print_key(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t set_key(sgx_enclave_id_t eid, unsigned int a)
{
	sgx_status_t status;
	ms_set_key_t ms;
	ms.ms_a = a;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t keygen(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t get_key(sgx_enclave_id_t eid, unsigned int* retval)
{
	sgx_status_t status;
	ms_get_key_t ms;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

