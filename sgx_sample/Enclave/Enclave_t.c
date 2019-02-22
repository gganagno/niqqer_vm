#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_print_secret(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	print_secret();
	return status;
}

static sgx_status_t SGX_CDECL sgx_set_secret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_set_secret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_set_secret_t* ms = SGX_CAST(ms_set_secret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	set_secret(ms->ms_a);


	return status;
}

static sgx_status_t SGX_CDECL sgx_addition(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_addition_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_addition_t* ms = SGX_CAST(ms_addition_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	addition(ms->ms_a, ms->ms_b);


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_secret(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_secret_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_secret_t* ms = SGX_CAST(ms_get_secret_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_secret();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_print_secret, 0},
		{(void*)(uintptr_t)sgx_set_secret, 0},
		{(void*)(uintptr_t)sgx_addition, 0},
		{(void*)(uintptr_t)sgx_get_secret, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][4];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL print_data(unsigned int got)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_print_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_data_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_data_t));
	ocalloc_size -= sizeof(ms_print_data_t);

	ms->ms_got = got;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print(char* value)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_value = value ? strlen(value) + 1 : 0;

	ms_ocall_print_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_t);
	void *__tmp = NULL;

	void *__tmp_value = NULL;

	CHECK_ENCLAVE_POINTER(value, _len_value);

	ocalloc_size += (value != NULL) ? _len_value : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_t));
	ocalloc_size -= sizeof(ms_ocall_print_t);

	if (value != NULL) {
		ms->ms_value = (char*)__tmp;
		__tmp_value = __tmp;
		if (memcpy_s(__tmp_value, ocalloc_size, value, _len_value)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_value);
		ocalloc_size -= _len_value;
	} else {
		ms->ms_value = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (value) {
			size_t __tmp_len_value;
			if (memcpy_s((void*)value, _len_value, __tmp_value, _len_value)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
			((char*)value)[_len_value - 1] = '\0';
			__tmp_len_value = strlen(value) + 1;
			memset(value +__tmp_len_value - 1, 0, _len_value -__tmp_len_value);
		}
	}
	sgx_ocfree();
	return status;
}

