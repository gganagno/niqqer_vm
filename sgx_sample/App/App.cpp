#include <unistd.h>
#include <stdio.h>

#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_tcrypto.h"
#define ENCLAVE_FILE "enclave.signed.so"

void
print_data(unsigned int got){
	printf("The secret is: %u\n", got);
}

void
ocall_print(char * value){
    int i;
    for(i = 0; i < 32; i++){
	printf("%2.2x", value[i]);
    }
}



int
main(int argc, char *argv[])
{
	unsigned int secret;
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
	printf("USER_SIDE    -> ENCLAVE_SIDE = ECALL\n");
	printf("ENCLAVE_SIDE -> USER_SIDE    = OCALL\n");
	/* print the secret  */
	printf("(ECALL) -> (OCALL)\t");
	print_secret(eid);

	/* set the secret */
	printf("(ECALL)\tSET SECRET = 3\n");
	set_secret(eid, 3);

	/* get the secret */
	get_secret(eid, &secret);
	printf("(ECALL)\tGot secret:%u\n", secret);

	/* perform the addition */ 
	printf("(ECALL)\tAdd 4 + 5\n");
	addition(eid, 4, 5);

	/* print the result */
	printf("(ECALL) -> (OCALL)\t");
	print_secret(eid);
	get_secret(eid, &secret);
	printf("(ECALL)\tGot secret:%u\n", secret); 
    
}
