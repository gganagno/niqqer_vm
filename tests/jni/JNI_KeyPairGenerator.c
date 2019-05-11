#include <jni.h>
#include <stdio.h>
#include "JNI_KeyGenerator.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern void wrapper_init_enclave();

extern int wrapper_rsa_keygen(int size);

extern void wrapper_rsa_print_key(int);

extern char *wrapper_rsa_get_pubkey(int);
extern char *wrapper_rsa_get_privkey(int);



JNIEXPORT int JNICALL Java_com_sun_max_vm_jdk_jni_1rsa_1helper_SGX_1KeyPairGenerator_1generateKey(JNIEnv *env, jobject thisObj, int size) {
	int id;
	char *buff;
	char *res;
	id = 0;
	buff = NULL;
	res = NULL;
    printf("EDWWWWWWWWWWWWWWWW!\n");
	wrapper_init_enclave();
	id = wrapper_rsa_keygen(size);
	return id;
}



JNIEXPORT jstring JNICALL Java_com_sun_max_vm_jdk_jni_1rsa_1helper_SGX_1KeyPairGenerator_1get_1pubkey(JNIEnv *env, jobject thisObj, int id) {


	char *buff;
	buff = NULL;
	buff = wrapper_rsa_get_pubkey(id);
	printf("NIQQER_JNI: Public key = \n%s\n", buff);
	jstring result = (*env)->NewStringUTF(env, buff);
	return result;
}

JNIEXPORT jstring JNICALL Java_com_sun_max_vm_jdk_jni_1rsa_1helper_SGX_1KeyPairGenerator_1get_1privkey(JNIEnv *env, jobject thisObj, int id) {
	char *buff;
	buff = NULL;
	buff = wrapper_rsa_get_privkey(id);
	printf("NIQQER_JNI: Private key = \n%s\n", buff);
	jstring result = (*env)->NewStringUTF(env, buff);
	return result;
}
