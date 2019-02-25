// Save as "HelloJNI.c"
#include <jni.h>        // JNI header provided by JDK
#include <stdio.h>      // C Standard IO Header
#include "JNI_KeyGenerator.h"   // Generated


#include <unistd.h>
#include <stdio.h>



extern unsigned int wrapper_init_enclave();

extern unsigned int wrapper_keygen();

extern unsigned int wrapper_print_key();

extern unsigned int wrapper_get_key();


JNIEXPORT int JNICALL Java_com_sun_max_vm_jdk_jni_1helper_SGX_1KeyGenerator(JNIEnv *env, jobject thisObj) {

	printf("Entry Java_com_sun_max_vm_jdk_jni_1helper_SGX_1KeyGenerator!\n");

	unsigned int id = wrapper_init_enclave();

	wrapper_keygen(id);

	unsigned int key;

	key = 66657;

	printf("c: key is %d\n",key );
	wrapper_print_key(id);
	return key;

}

