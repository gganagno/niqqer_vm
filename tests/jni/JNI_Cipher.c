// Save as "HelloJNI.c"
#include <jni.h>        // JNI header provided by JDK
#include <stdio.h>      // C Standard IO Header
#include "JNI_Cipher.h"   // Generated


#include <unistd.h>
#include <stdio.h>



extern unsigned int wrapper_init_enclave();

extern unsigned int wrapper_keygen();

extern unsigned int wrapper_print_key();

extern unsigned int wrapper_get_key();


JNIEXPORT void JNICALL Java_com_sun_max_vm_jdk_jni_1cipher_1helper_SGX_1Cipher_1init(JNIEnv *env, jobject thisObj) {

	printf("Entry Java_com_sun_max_vm_jdk_jni_1cipher_1helper_SGX_1Cipher_1init!\n");
}

JNIEXPORT char * JNICALL Java_com_sun_max_vm_jdk_jni_1cipher_1helper_SGX_1Cipher_1update(JNIEnv *env, jobject thisObj) {

	printf("Entry Java_com_sun_max_vm_jdk_jni_1cipher_1helper_SGX_1Cipher_1update!\n");
	return NULL;

}

JNIEXPORT char * JNICALL Java_com_sun_max_vm_jdk_jni_1cipher_1helper_SGX_1Cipher_1dofinal(JNIEnv *env, jobject thisObj) {

	printf("Entry Java_com_sun_max_vm_jdk_jni_1cipher_1helper_SGX_1Cipher_1dofinal!\n");
	return NULL;

}

