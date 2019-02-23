#include <unistd.h>
#include <stdio.h>

#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_tcrypto.h"

#define ENCLAVE_FILE "enclave.signed.so"

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


sgx_enclave_id_t init_enclave(){

	sgx_enclave_id_t eid = 0 ;
	sgx_status_t ret = SGX_SUCCESS;

	sgx_launch_token_t token = {0};
	int updated = 0;

	/* create the enclave */
	printf("Creating Enclave\n");

	ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token,
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



int
main(int argc, char *argv[])
{
	// unsigned int key;

	// sgx_enclave_id_t eid = 0 ;
	// sgx_status_t ret = SGX_SUCCESS;

	// sgx_launch_token_t token = {0};
	// int updated = 0;

	// /* create the enclave */
	// printf("Creating Enclave\n");

	// ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token,
	//     &updated, &eid, NULL);

	// if (ret != SGX_SUCCESS){
	// 	printf("\nERROR: failed to create enclave, code: %#x\n", ret);
	// }

	// printf("USER_SIDE    -> ENCLAVE_SIDE = ECALL\n");

	// printf("ENCLAVE_SIDE -> USER_SIDE    = OCALL\n");
	// /* print the key  */
	// printf("(ECALL) -> (OCALL)\t");
	// print_key(eid);

	// /* set the key */
	// printf("(ECALL)\tSET key = 3\n");
	// set_key(eid, 3);

	// /* get the key */
	// get_key(eid, &key);
	// printf("(ECALL)\tGot key:%u\n", key);

	// /* keygen */
	// keygen(eid);
	// printf("(ECALL)\tGot key:%u\n", key);

	// /* print the result */
	// printf("(ECALL) -> (OCALL)\t");
	// print_key(eid);
	// get_key(eid, &key);
	// printf("(ECALL)\tGot key:%u\n", key); 
    
}
