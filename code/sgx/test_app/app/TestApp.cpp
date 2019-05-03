#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <pthread.h>

# define MAX_PATH FILENAME_MAX


#include <sgx_urts.h>

#include "TestApp.h"

#include "TestEnclave_u.h"


#define debug_print(...) printf("NIQQER_VM NATIVE: ");printf( __VA_ARGS__);

/* Global EID shared by multiple threads */


extern "C" {
	static int init = 0;
	sgx_enclave_id_t eid = 0;
	void
		print_rsa_key(uint8_t *r){
			int i;
			for (i = 0; i < 32; i++)
				printf("%x", r[i]);
			printf("\n");
		}

	void
		print_data(char *got, int len)
		{
			int i;
			debug_print("The Key is\n||");
			for (i = 0; i < len; i++) {
				printf("%u", got[i]);
			}
			printf("||\n");
		}


	void
		ocall_print(char *value)
		{
			int i;
			for(i = 0; i < 32; i++){
				debug_print("%2.2x", value[i]);
			}
		}

	void
		wrapper_init_enclave()
		{
			if (init == 0) {
				init = 1;
				sgx_launch_token_t token = {0};
				int updated;
				char buffer[1024];
				const char* s = getenv("MAXINE_HOME");

				eid = 0 ;
				updated = 0;
				sgx_status_t ret;
				ret = SGX_SUCCESS;
				memset(buffer, 0, 1024);
				/* create the enclave */
				debug_print("Creating Enclave\n");
				sprintf(buffer, "%s/com.oracle.max.vm.native/generated/linux/libenclave.signed.so", s);

				ret = sgx_create_enclave(buffer, SGX_DEBUG_FLAG, &token,
						&updated, &eid, NULL);

				if (ret != SGX_SUCCESS){
					debug_print("\nERROR: failed to create enclave, code: %#x\n", ret);
					exit(EXIT_FAILURE);
				}
				startup(eid);
			}
		}

	void
		wrapper_print_key(int id)
		{
			print_key(eid, id);
		}



	char *
		wrapper_get_key(int id, int size)
		{
			char *key;
			key = (char *)calloc(sizeof(char), size);
			get_key(eid, id, key, size);
			return strdup(key);
		}

	int
		wrapper_keygen(int size)
		{
			int id;
			keygen(eid, &id, size);
			return id;
		}

	char *
		wrapper_rsa_get_pubkey(int id)
		{
			char *key = NULL;
			get_pubkey(eid, &key, id);
			return strdup(key);
		}
	char *
		wrapper_rsa_get_privkey(int id)
		{
			char *key = NULL;
			get_privkey(eid, &key, id);
			return strdup(key);
		}

	void
		wrapper_rsa_print_key(int id)
		{
			print_key(eid, id);
		}

	int
		wrapper_rsa_keygen(int size)
		{
			int id;
			generate_keypair(eid, &id, size);
			return id;
		}



	unsigned char *
		wrapper_rsa_decrypt(int id, unsigned char *string)
		{
			unsigned char *plain;
			rsa_decrypt(eid, &plain, id, string);
			return plain;
		}

	int
	wrapper_rsa_get_key_size(int id)
	{
		int res;
		rsa_get_key_size(eid, &res, id);
		printf("RES = %d\n", res);
		return res;
	}
	unsigned char *
		wrapper_rsa_encrypt(int id, char *string)
		{
			unsigned char *encrypted;
			rsa_encrypt(eid, &encrypted, id, string);
			return encrypted;
		}

	char *
		wrapper_aes_encrypt(int id, char *string, int len)
		{
			char *encrypted;
			aes_encrypt(eid, &encrypted, id, string, len);
			return encrypted;
		}
	char *
		wrapper_aes_decrypt(int id, char *string, int len)
		{
			char *decrypted;
			aes_decrypt(eid, &decrypted, id, string, len);
			return decrypted;
		}



	/* debugging */
	int main() {
		int id;
		wrapper_init_enclave();
		id = wrapper_rsa_keygen(2048);
		char *xd, *plain;
		//printf("%s\n", (xd = wrapper_rsa_encrypt( id, "lala")));
		//printf("%s\n", wrapper_rsa_decrypt( id, xd));
		wrapper_rsa_get_pubkey(id);
	}
	typedef struct _sgx_errlist_t {
		sgx_status_t err;
		const char *msg;
		const char *sug; /* Suggestion */
	} sgx_errlist_t;

	/* Error code returned by sgx_create_enclave */
	static sgx_errlist_t sgx_errlist[] = {
		{
			SGX_ERROR_UNEXPECTED,
			"Unexpected error occurred.",
			NULL
		},
		{
			SGX_ERROR_INVALID_PARAMETER,
			"Invalid parameter.",
			NULL
		},
		{
			SGX_ERROR_OUT_OF_MEMORY,
			"Out of memory.",
			NULL
		},
		{
			SGX_ERROR_ENCLAVE_LOST,
			"Power transition occurred.",
			"Please refer to the sample \"PowerTransition\" for details."
		},
		{
			SGX_ERROR_INVALID_ENCLAVE,
			"Invalid enclave image.",
			NULL
		},
		{
			SGX_ERROR_INVALID_ENCLAVE_ID,
			"Invalid enclave identification.",
			NULL
		},
		{
			SGX_ERROR_INVALID_SIGNATURE,
			"Invalid enclave signature.",
			NULL
		},
		{
			SGX_ERROR_OUT_OF_EPC,
			"Out of EPC memory.",
			NULL
		},
		{
			SGX_ERROR_NO_DEVICE,
			"Invalid Intel® Software Guard Extensions device.",
			"Please make sure Intel® Software Guard Extensions module is enabled in the BIOS, and install Intel® Software Guard Extensions driver afterwards."
		},
		{
			SGX_ERROR_MEMORY_MAP_CONFLICT,
			"Memory map conflicted.",
			NULL
		},
		{
			SGX_ERROR_INVALID_METADATA,
			"Invalid enclave metadata.",
			NULL
		},
		{
			SGX_ERROR_DEVICE_BUSY,
			"Intel® Software Guard Extensions device was busy.",
			NULL
		},
		{
			SGX_ERROR_INVALID_VERSION,
			"Enclave version was invalid.",
			NULL
		},
		{
			SGX_ERROR_INVALID_ATTRIBUTE,
			"Enclave was not authorized.",
			NULL
		},
		{
			SGX_ERROR_ENCLAVE_FILE_ACCESS,
			"Can't open enclave file.",
			NULL
		},
	};

	/* Check error conditions for loading enclave */
	void print_error_message(sgx_status_t ret)
	{
		size_t idx = 0;
		size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

		for (idx = 0; idx < ttl; idx++) {
			if(ret == sgx_errlist[idx].err) {
				if(NULL != sgx_errlist[idx].sug)
					printf("Info: %s\n", sgx_errlist[idx].sug);
				printf("Error: %s\n", sgx_errlist[idx].msg);
				break;
			}
		}

		if (idx == ttl)
			printf("Error: Unexpected error occurred [0x%x].\n", ret);
	}


	/* OCall functions */
	void uprint(const char *str)
	{
		/* Proxy/Bridge will check the length and null-terminate 
		 * the input string to prevent buffer overflow. 
		 */
		printf("%s", str);
		fflush(stdout);
	}


	void usgx_exit(int reason)
	{
		printf("usgx_exit: %d\n", reason);
		exit(reason);
	}



}
