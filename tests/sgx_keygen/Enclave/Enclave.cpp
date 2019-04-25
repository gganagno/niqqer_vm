#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include "sgx_defs.h"
#include "sgx_trts.h"
using namespace std;
// SGX KeyGenerator

/* 100 keys of 16 byte len */
char *key_array[100];
int active_ids = 0;

void
print_key(int id){
    print_data(key_array[id]);
}

void
get_key(int id, char *got, int size){
    
    memcpy(got, key_array[id], size);
    //got = key_array[id];
}


// void
// set_key(unsigned int a){
// 	key = a;
// 	return;
// }

int
keygen(int size){
    int i;
    key_array[active_ids] = (char *)malloc(size * sizeof(char));
    sgx_read_rand((unsigned char *) key_array[active_ids], size);
    key_array[active_ids][size -1] = '\0';
    
    //memcpy(key_array[active_ids], b, size);
    return active_ids;
}


