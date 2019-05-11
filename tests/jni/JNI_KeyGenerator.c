#include <jni.h>
#include <stdio.h>
#include "JNI_KeyGenerator.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern void wrapper_init_enclave();

extern int wrapper_keygen(int size);

extern void wrapper_print_key(int);

extern char *wrapper_get_key(int, int);



JNIEXPORT int JNICALL Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1getid(JNIEnv *env, jobject thisObj, int size) {

	int id;
	size /= 8;
	wrapper_init_enclave();
	id = wrapper_keygen(size);
	return id;
}
JNIEXPORT jstring JNICALL Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1generateKey(JNIEnv *env, jobject thisObj, int size, int id) {
	int i = 0;
	char *buff;
	char *res;

	size /= 8;
	printf("ID = %d\n", id);
	//wrapper_print_key(id);
	res = wrapper_get_key(id, size);
	buff = malloc(size);
	memset(buff, 0, size);
	strcpy(buff, res);
	/* normalize the String */
	for (i = 0; i < size; i++){
		sprintf(&buff[i], "%u", res[i]);

	}
	jstring result = (*env)->NewStringUTF(env, buff);
	return result;
}
