#include <jni.h>
#include <stdio.h>
#include "JNI_KeyGenerator.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

extern void wrapper_init_enclave();

extern int wrapper_keygen();

extern void wrapper_print_key(int);

extern char *wrapper_get_key(int);



JNIEXPORT jstring JNICALL Java_com_sun_max_vm_jdk_jni_1keygenerator_1helper_SGX_1KeyGenerator_1generateKey(JNIEnv *env, jobject thisObj) {

        int eid;
	int id = 5;
	char *buff;
        char *res;
    
        wrapper_init_enclave();
	id = wrapper_keygen();
        printf("ID = %d\n", id);
	wrapper_print_key(id);
	res = wrapper_get_key(id);
        buff = malloc(16);
        strcpy(buff, res);
        printf("|%s|\n", buff);
        int i = 0;
        for (i = 0; i < 16; i++){
            sprintf(&buff[i], "%02.x", res[i]);
            
        }
	jstring result = (*env)->NewStringUTF(env, buff);
	return result;
}
