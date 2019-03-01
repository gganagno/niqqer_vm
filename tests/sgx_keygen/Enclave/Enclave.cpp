#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
// SGX KeyGenerator

char key[1024];


void
print_key(){
	print_data(key);
}

void
get_key(char * got){
//?
}


// void
// set_key(unsigned int a){
// 	key = a;
// 	return;
// }


void
keygen(){
	memset(key, 0 ,1024);
	snprintf(key,25,"abcdefghijklmopqrstuvwxyz");
}


