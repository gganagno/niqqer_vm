#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include <string.h>



// SGX KeyGenerator

unsigned int key = 0;


void
print_key(){
	print_data(key);
}

unsigned int
get_key(){
	return key;
}


void
set_key(unsigned int a){
	key = a;
	return;
}


void
keygen(){
	key = 666;
	return;
}


