#include <unistd.h>
#include <stdio.h>
#include <limits.h>

#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_tcrypto.h"

#define ENCLAVE_FILE "libenclave.signed.so"


extern "C" {

void
print_data(unsigned int got){

	printf("The key is: %u\n", got);
}


void
ocall_print(char * value){
    int i;
    for(i = 0; i < 32; i++){
	printf("%2.2x", value[i]);
    }
}


unsigned int wrapper_init_enclave(){

	sgx_enclave_id_t eid = 0 ;
	sgx_status_t ret = SGX_SUCCESS;

	sgx_launch_token_t token = {0};
	int updated = 0;

	char buffer[1024];

	/* create the enclave */
	printf("Creating Enclave\n");

	const char* s = getenv("LD_LIBRARY_PATH");

	memset(buffer, 0 ,1024);
	sprintf(buffer, "%slibenclave.signed.so", s);

	ret = sgx_create_enclave(buffer, SGX_DEBUG_FLAG, &token,
	    &updated, &eid, NULL);

	if (ret != SGX_SUCCESS){
		printf("\nERROR: failed to create enclave, code: %#x\n", ret);
	}

	return eid;
}

void wrapper_print_key(sgx_enclave_id_t eid){
	print_key(eid);
}


unsigned int wrapper_get_key(sgx_enclave_id_t eid,unsigned int key){
	return get_key(eid,&key);
}


void wrapper_set_key(sgx_enclave_id_t eid,unsigned int a){
	set_key(eid,a);
}


void wrapper_keygen(sgx_enclave_id_t eid){
	keygen(eid);
}



// int
// main(int argc, char *argv[]){}
     
}

