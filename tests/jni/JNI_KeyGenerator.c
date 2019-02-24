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

	printf("entry myniqqerinoz!\n");
	unsigned int id = wrapper_init_enclave();

	wrapper_keygen(id);
	unsigned int key;
	wrapper_get_key(id,key);

	key = 66657;
	wrapper_print_key(id);
	printf("Hello World myniqqerinoz!\n");
	return key;

}

