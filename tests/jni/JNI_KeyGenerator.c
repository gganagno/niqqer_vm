#include <jni.h>
#include <stdio.h>
#include "JNI_KeyGenerator.h"
#include <unistd.h>
#include <stdlib.h>

extern unsigned int wrapper_init_enclave();

extern void wrapper_keygen(unsigned int );

extern void wrapper_print_key(unsigned int );

extern void wrapper_get_key(unsigned int, char * key);


// JNIEXPORT void JNICALL Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1init(JNIEnv *env, jobject thisObj) {
// 	printf("Entry Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1init!\n");
// }


JNIEXPORT jstring JNICALL Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1generateKey(JNIEnv *env, jobject thisObj) {

	// printf("Entry Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1generateKey!\n");

	unsigned int id = wrapper_init_enclave();

	wrapper_keygen(id);

	char * buff = (char *)malloc(1024);

	wrapper_print_key(id);

	wrapper_get_key(id,buff);
	
	printf("generate.c : %s\n",buff );	

	jstring result = (*env)->NewStringUTF(env,buff);

	return result;
}