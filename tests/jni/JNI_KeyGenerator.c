// Save as "HelloJNI.c"
#include <jni.h>        // JNI header provided by JDK
#include <stdio.h>      // C Standard IO Header
#include "JNI_KeyGenerator.h"   // Generated


#include <unistd.h>
#include <stdio.h>

#include <stdlib.h>

extern unsigned int wrapper_init_enclave();

extern unsigned int wrapper_keygen();

extern unsigned int wrapper_print_key();

extern unsigned int wrapper_get_key();


JNIEXPORT void JNICALL Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1init(JNIEnv *env, jobject thisObj) {

	printf("Entry Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1init!\n");


}


JNIEXPORT char * JNICALL Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1generateKey(JNIEnv *env, jobject thisObj) {

	printf("Entry Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1generateKey!\n");

	unsigned int id = wrapper_init_enclave();

	wrapper_keygen(id);

	char *buff = (char *)malloc(1024);

	buff = "abcdefghijklmopqrstuvwxyz";

	printf("c: key is %s\n",buff );

	wrapper_print_key(id);

	return buff;

}