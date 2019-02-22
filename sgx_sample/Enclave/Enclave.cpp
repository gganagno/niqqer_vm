#include "Enclave_t.h"
#include "sgx_tcrypto.h"
#include <string.h>
unsigned int secret = 0;


void
print_secret(){
	print_data(secret);
}

unsigned int
get_secret(){
	return secret;
}


void
set_secret(unsigned int a){
	secret = a;
	return;
}


void
addition(unsigned int a, unsigned int b){
	secret =  a + b;
	return;
}


