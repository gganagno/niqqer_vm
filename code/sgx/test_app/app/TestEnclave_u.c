#include "TestEnclave_u.h"
#include <errno.h>

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
	char* ms_retval;
	int ms_id;
	char* ms_msg;
} ms_rsa_encrypt_t;

typedef struct ms_rsa_decrypt_t {
	char* ms_retval;
	int ms_id;
	char* ms_msg;
} ms_rsa_decrypt_t;

typedef struct ms_aes_encrypt_t {
	char* ms_retval;
	int ms_id;
	char* ms_msg;
	int ms_len;
} ms_aes_encrypt_t;

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

static sgx_status_t SGX_CDECL TestEnclave_uprint(void* pms)
{
	ms_uprint_t* ms = SGX_CAST(ms_uprint_t*, pms);
	uprint(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_usgx_exit(void* pms)
{
	ms_usgx_exit_t* ms = SGX_CAST(ms_usgx_exit_t*, pms);
	usgx_exit(ms->ms_reason);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_print_rsa_key(void* pms)
{
	ms_print_rsa_key_t* ms = SGX_CAST(ms_print_rsa_key_t*, pms);
	print_rsa_key(ms->ms_r);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_print_data(void* pms)
{
	ms_print_data_t* ms = SGX_CAST(ms_print_data_t*, pms);
	print_data(ms->ms_got, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_ocall_print(void* pms)
{
	ms_ocall_print_t* ms = SGX_CAST(ms_ocall_print_t*, pms);
	ocall_print(ms->ms_value);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[11];
} ocall_table_TestEnclave = {
	11,
	{
		(void*)TestEnclave_uprint,
		(void*)TestEnclave_usgx_exit,
		(void*)TestEnclave_print_rsa_key,
		(void*)TestEnclave_print_data,
		(void*)TestEnclave_ocall_print,
		(void*)TestEnclave_u_sgxssl_ftime,
		(void*)TestEnclave_sgx_oc_cpuidex,
		(void*)TestEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)TestEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)TestEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t generate_keypair(sgx_enclave_id_t eid, int* retval, int size)
{
	sgx_status_t status;
	ms_generate_keypair_t ms;
	ms.ms_size = size;
	status = sgx_ecall(eid, 0, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t print_key(sgx_enclave_id_t eid, int id)
{
	sgx_status_t status;
	ms_print_key_t ms;
	ms.ms_id = id;
	status = sgx_ecall(eid, 1, &ocall_table_TestEnclave, &ms);
	return status;
}

sgx_status_t keygen(sgx_enclave_id_t eid, int* retval, int size)
{
	sgx_status_t status;
	ms_keygen_t ms;
	ms.ms_size = size;
	status = sgx_ecall(eid, 2, &ocall_table_TestEnclave, &ms);
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
	status = sgx_ecall(eid, 3, &ocall_table_TestEnclave, &ms);
	return status;
}

sgx_status_t get_pubkey(sgx_enclave_id_t eid, char** retval, int id)
{
	sgx_status_t status;
	ms_get_pubkey_t ms;
	ms.ms_id = id;
	status = sgx_ecall(eid, 4, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t get_privkey(sgx_enclave_id_t eid, char** retval, int id)
{
	sgx_status_t status;
	ms_get_privkey_t ms;
	ms.ms_id = id;
	status = sgx_ecall(eid, 5, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t rsa_encrypt(sgx_enclave_id_t eid, char** retval, int id, char* msg)
{
	sgx_status_t status;
	ms_rsa_encrypt_t ms;
	ms.ms_id = id;
	ms.ms_msg = msg;
	status = sgx_ecall(eid, 6, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t rsa_decrypt(sgx_enclave_id_t eid, char** retval, int id, char* msg)
{
	sgx_status_t status;
	ms_rsa_decrypt_t ms;
	ms.ms_id = id;
	ms.ms_msg = msg;
	status = sgx_ecall(eid, 7, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t aes_encrypt(sgx_enclave_id_t eid, char** retval, int id, char* msg, int len)
{
	sgx_status_t status;
	ms_aes_encrypt_t ms;
	ms.ms_id = id;
	ms.ms_msg = msg;
	ms.ms_len = len;
	status = sgx_ecall(eid, 8, &ocall_table_TestEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t startup(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 9, &ocall_table_TestEnclave, NULL);
	return status;
}

