#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#define debug_print(...) printf("NIQQER_VM NATIVE: ");printf( __VA_ARGS__);
#define ENCLAVE_FILE "libenclave.signed.so"

sgx_enclave_id_t eid;

extern "C" {

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
            for (i = 0; i < len; i++)
                debug_print("%x", got[i]);
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
            int step;
            sgx_status_t error;
            Test(eid, &step, &error);
            
            if (error) 
                printf("Failed on step %d\n", error);
            else
                printf("COMPLETE!\n");
            exit(-1);
        }

    void wrapper_print_key(int id){
        print_key(eid, id);
    }



    char *wrapper_get_key(int id, int size){
        char *key;
        key = (char *)calloc(sizeof(char), size);
        get_key(eid, id, key, size);
        return strdup(key);
    }

    int wrapper_keygen(int size){
        int id;
        debug_print("SIZE = %d\n", size);
        keygen(eid, &id, size);
        debug_print("MY ID = %d\n", id);
        return id;
    }


    char *wrapper_rsa_get_key(int id, int size){
        char *key;
        key = (char *)calloc(sizeof(char), size);
        get_key(eid, id, key, size);
        return strdup(key);
    }

    void wrapper_rsa_print_key(int id){
        print_key(eid, id);
    }

    int wrapper_rsa_keygen(int size){
        int id;
        debug_print("SIZE = %d\n", size);
        keygen(eid, &id, size);
        debug_print("MY ID = %d\n", id);
        return id;
    }
}

