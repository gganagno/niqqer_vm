// Save as "HelloJNI.c"
#include <jni.h>        // JNI header provided by JDK
#include <stdio.h>      // C Standard IO Header
#include "JNI_KeyGenerator.h"   // Generated


#include <unistd.h>
#include <stdio.h>

// #include "sgx_urts.h"
// #include "Enclave_u.h"
// #include "sgx_tcrypto.h"


extern void wrapper_keygen(unsigned int eid);
extern void wrapper_print_key(unsigned int id);
extern unsigned int init_enclave();

// Implementation of the native method KeyGenerator()
JNIEXPORT void JNICALL Java_com_sun_max_vm_jdk_jni_1helper_SGX_1KeyGenerator(JNIEnv *env, jobject thisObj) {

   unsigned int id = init_enclave();
   wrapper_keygen(id);
   wrapper_print_key(id);
   printf("Hello World myniqqerinoz!\n");
   return;

}

