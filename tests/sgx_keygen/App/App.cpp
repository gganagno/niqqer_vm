#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include "sgx_urts.h"
#include "Enclave_u.h"

#define ENCLAVE_FILE "libenclave.signed.so"

        sgx_enclave_id_t eid;

extern "C" {

    void
    print_data(char *got)
    {
        printf("The key is: %.*s\n", 16, got);
    }


    void
    ocall_print(char *value)
    {
            int i;
            for(i = 0; i < 32; i++){
                printf("%2.2x", value[i]);
            }
        }

    void
    wrapper_init_enclave()
    {

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
        printf("Creating Enclave\n");
        sprintf(buffer, "%s/com.oracle.max.vm.native/generated/linux/libenclave.signed.so", s);

        ret = sgx_create_enclave(buffer, SGX_DEBUG_FLAG, &token,
                &updated, &eid, NULL);

        if (ret != SGX_SUCCESS){
            printf("\nERROR: failed to create enclave, code: %#x\n", ret);
            exit(EXIT_FAILURE);
        }

    }

    void wrapper_print_key(int id){
        print_key(eid, id);
    }


    char *wrapper_get_key(int id){
        char key[16];
        get_key(eid, id, key);
        return strdup(key);
}


    int wrapper_keygen(){
        int id;
        keygen(eid, &id);
        printf("MY ID = %d\n", id);
        return id;
    }


}

