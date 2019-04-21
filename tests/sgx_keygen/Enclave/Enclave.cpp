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
char key_array[100][16];
int active_ids = 0;

void
print_key(int id){
    print_data(key_array[id]);
}

void
get_key(int id, char got[16]){
    
    memcpy(got, key_array[id], 16);
}


// void
// set_key(unsigned int a){
// 	key = a;
// 	return;
// }

int
keygen(){
    int i;
    char b[16];
    sgx_read_rand((unsigned char *)b, 16);
    b[sizeof(b) - 1] = '\0';
    memcpy(key_array[active_ids], b, 16);
    return active_ids;
}


