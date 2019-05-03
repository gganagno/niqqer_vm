#include "TestEnclave_t.h"

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


typedef struct ms_generate_keypair_t {
	int ms_retval;
	int ms_size;
} ms_generate_keypair_t;

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

typedef struct ms_get_pubkey_t {
	char* ms_retval;
	int ms_id;
} ms_get_pubkey_t;

typedef struct ms_get_privkey_t {
	char* ms_retval;
	int ms_id;
} ms_get_privkey_t;

typedef struct ms_rsa_encrypt_t {
	unsigned char* ms_retval;
	int ms_id;
	char* ms_msg;
} ms_rsa_encrypt_t;

typedef struct ms_rsa_get_key_size_t {
	int ms_retval;
	int ms_id;
} ms_rsa_get_key_size_t;

typedef struct ms_rsa_decrypt_t {
	unsigned char* ms_retval;
	int ms_id;
	unsigned char* ms_msg;
} ms_rsa_decrypt_t;

typedef struct ms_aes_encrypt_t {
	char* ms_retval;
	int ms_id;
	char* ms_msg;
	int ms_len;
} ms_aes_encrypt_t;

typedef struct ms_aes_decrypt_t {
	char* ms_retval;
	int ms_id;
	char* ms_msg;
	int ms_len;
} ms_aes_decrypt_t;

typedef struct ms_uprint_t {
	const char* ms_str;
} ms_uprint_t;

typedef struct ms_usgx_exit_t {
	int ms_reason;
} ms_usgx_exit_t;

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

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_generate_keypair(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_keypair_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generate_keypair_t* ms = SGX_CAST(ms_generate_keypair_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = generate_keypair(ms->ms_size);


	return status;
}

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

static sgx_status_t SGX_CDECL sgx_get_pubkey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_pubkey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_pubkey_t* ms = SGX_CAST(ms_get_pubkey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_pubkey(ms->ms_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_get_privkey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_privkey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_privkey_t* ms = SGX_CAST(ms_get_privkey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = get_privkey(ms->ms_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_rsa_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_rsa_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_rsa_encrypt_t* ms = SGX_CAST(ms_rsa_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_msg = ms->ms_msg;



	ms->ms_retval = rsa_encrypt(ms->ms_id, _tmp_msg);


	return status;
}

static sgx_status_t SGX_CDECL sgx_rsa_get_key_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_rsa_get_key_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_rsa_get_key_size_t* ms = SGX_CAST(ms_rsa_get_key_size_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = rsa_get_key_size(ms->ms_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_rsa_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_rsa_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_rsa_decrypt_t* ms = SGX_CAST(ms_rsa_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_msg = ms->ms_msg;



	ms->ms_retval = rsa_decrypt(ms->ms_id, _tmp_msg);


	return status;
}

static sgx_status_t SGX_CDECL sgx_aes_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_aes_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_aes_encrypt_t* ms = SGX_CAST(ms_aes_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_msg = ms->ms_msg;



	ms->ms_retval = aes_encrypt(ms->ms_id, _tmp_msg, ms->ms_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_aes_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_aes_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_aes_decrypt_t* ms = SGX_CAST(ms_aes_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_msg = ms->ms_msg;



	ms->ms_retval = aes_decrypt(ms->ms_id, _tmp_msg, ms->ms_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_startup(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	startup();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[12];
} g_ecall_table = {
	12,
	{
		{(void*)(uintptr_t)sgx_generate_keypair, 0},
		{(void*)(uintptr_t)sgx_print_key, 0},
		{(void*)(uintptr_t)sgx_keygen, 0},
		{(void*)(uintptr_t)sgx_get_key, 0},
		{(void*)(uintptr_t)sgx_get_pubkey, 0},
		{(void*)(uintptr_t)sgx_get_privkey, 0},
		{(void*)(uintptr_t)sgx_rsa_encrypt, 0},
		{(void*)(uintptr_t)sgx_rsa_get_key_size, 0},
		{(void*)(uintptr_t)sgx_rsa_decrypt, 0},
		{(void*)(uintptr_t)sgx_aes_encrypt, 0},
		{(void*)(uintptr_t)sgx_aes_decrypt, 0},
		{(void*)(uintptr_t)sgx_startup, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[11][12];
} g_dyn_entry_table = {
	11,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL uprint(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_uprint_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_uprint_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_uprint_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_uprint_t));
	ocalloc_size -= sizeof(ms_uprint_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL usgx_exit(int reason)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_usgx_exit_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_usgx_exit_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_usgx_exit_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_usgx_exit_t));
	ocalloc_size -= sizeof(ms_usgx_exit_t);

	ms->ms_reason = reason;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL print_rsa_key(uint8_t* r)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_print_rsa_key_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_print_rsa_key_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_print_rsa_key_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_print_rsa_key_t));
	ocalloc_size -= sizeof(ms_print_rsa_key_t);

	ms->ms_r = r;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL print_data(char* got, int len)
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
	ms->ms_len = len;
	status = sgx_ocall(3, ms);

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
	
	status = sgx_ocall(4, ms);

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

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		ms->ms_timeptr = (void*)__tmp;
		__tmp_timeptr = __tmp;
		memset(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}
	
	ms->ms_timeb_len = timeb_len;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

