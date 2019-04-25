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

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

typedef struct ms_print_data_t {
	char* ms_got;
} ms_print_data_t;

typedef struct ms_ocall_print_t {
	char* ms_value;
} ms_ocall_print_t;

static sgx_status_t SGX_CDECL sgx_print_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_print_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_print_key_t* ms = SGX_CAST(ms_print_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	print_key(ms->ms_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_keygen(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_keygen_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_keygen_t* ms = SGX_CAST(ms_keygen_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = keygen(ms->ms_size);


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_key(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_key_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_key_t* ms = SGX_CAST(ms_get_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_got = ms->ms_got;



	get_key(ms->ms_id, _tmp_got, ms->ms_size);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_print_key, 0},
		{(void*)(uintptr_t)sgx_keygen, 0},
		{(void*)(uintptr_t)sgx_get_key, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][3];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, },
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL print_data(char got[16])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_got = 16 * sizeof(char);

	ms_print_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_data_t);
	void *__tmp = NULL;

	void *__tmp_got = NULL;

	CHECK_ENCLAVE_POINTER(got, _len_got);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (got != NULL) ? _len_got : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_data_t));
	ocalloc_size -= sizeof(ms_print_data_t);

	if (got != NULL) {
		ms->ms_got = (char*)__tmp;
		__tmp_got = __tmp;
		if (_len_got % sizeof(*got) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_got, ocalloc_size, got, _len_got)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_got);
		ocalloc_size -= _len_got;
	} else {
		ms->ms_got = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (got) {
			if (memcpy_s((void*)got, _len_got, __tmp_got, _len_got)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
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

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (value != NULL) ? _len_value : 0))
		return SGX_ERROR_INVALID_PARAMETER;

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
		if (_len_value % sizeof(*value) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
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

