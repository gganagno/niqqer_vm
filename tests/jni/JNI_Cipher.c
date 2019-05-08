#include <jni.h>        // JNI header provided by JDK
#include <stdio.h>      // C Standard IO Header
#include "JNI_Cipher.h"   // Generated
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define printf(...) ;

extern unsigned int wrapper_init_enclave();

extern unsigned int wrapper_keygen();
extern int wrapper_rsa_get_key_size(int);
extern unsigned int wrapper_print_key();
extern unsigned char *wrapper_aes_encrypt(int, char *, int);
extern unsigned char *wrapper_aes_decrypt(int, char *, int);
extern unsigned char *wrapper_rsa_encrypt(int, char *);
extern unsigned char *wrapper_rsa_decrypt(int, char *);
extern unsigned int wrapper_aes_getbytes(int);

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


JNIEXPORT jbyteArray JNICALL Java_com_sun_max_vm_jdk_jni_1cipher_1helper_SGX_1Cipher_1dofinal_1xd(JNIEnv *env, jobject thisObj, int id, jbyteArray b, int mode, int algo) {
	// obtain the array elements
	int keysize = wrapper_rsa_get_key_size(id);
	printf("KEY SIZE = %d\n", keysize);
	jbyte* elements = (*env)->GetByteArrayElements(env, b, NULL);
	jsize num_bytes = (*env)->GetArrayLength(env, b);
	printf("STRING = %s\n", elements);
	printf("OPMODE = %d\n", mode);
	unsigned char *res;
	printf("Entry Java_com_sun_max_vm_jdk_jni_1cipher_1helper_SGX_1Cipher_1dofinal! bytearray\n");
	if (mode == 1) {
		printf("Encryption!!\n");
		if (algo == 1){
			res = wrapper_rsa_encrypt(id, (char *)elements);
			char *lala = (char *)malloc(keysize + 1);
			memcpy(lala, res, keysize);
			jbyteArray data = (*env)->NewByteArray(env, keysize);
			if (data == NULL) {
				return NULL; //  out of memory error thrown
			}
			// creat bytes from byteUrl
			jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
			int i;
			for (i = 0; i < keysize; i++) {
				bytes[i] = res[i];
			}
			(*env)->SetByteArrayRegion(env, data, 0, keysize, bytes);
			
			return data;
		} else  {
			fprintf(stdout, "AESS!!\n");
			res = wrapper_aes_encrypt(id, (char *)elements, (int)num_bytes);
			num_bytes = wrapper_aes_getbytes(id);
			char *lala = (char *)calloc(num_bytes + 1, 1);
		
			memcpy(lala, res, num_bytes);
			jbyteArray data = (*env)->NewByteArray(env, num_bytes);
			if (data == NULL) 
				return NULL; //  out of memory error thrown
			jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
			int i;
			for (i = 0; i < num_bytes; i++)  {
				bytes[i] = res[i];
			}
			fprintf(stdout, "%.*s\n\n\n<<<<<<<\n", num_bytes, res);
			(*env)->SetByteArrayRegion(env, data, 0, num_bytes, bytes);
			return data;
		}

		}else {
			printf("Decryption\n");
			if (algo == 1) {
				res = wrapper_rsa_decrypt(id, (char *)elements);
				keysize = strlen((char *)res);
				res[keysize-1]='\0';
				printf("RESS %s\n", res);
				jbyteArray data = (*env)->NewByteArray(env, keysize);
				if (data == NULL) {
					return NULL; //  out of memory error thrown
				}

				// creat bytes from byteUrl
				jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
				int i;
				for (i = 0; i < keysize; i++) {
					bytes[i] = res[i];
				}

				// move from the temp structure to the java structure
				(*env)->SetByteArrayRegion(env, data, 0, keysize, bytes);
				return data;
			}else { 
				res = wrapper_aes_decrypt(id, (char *)elements, num_bytes);
				fprintf(stdout, "DECRYPTED:%s\n", res);
				keysize = strlen((char *)res);
				jbyteArray data = (*env)->NewByteArray(env, keysize);
				if (data == NULL) {
					return NULL; //  out of memory error thrown
				}

				// creat bytes from byteUrl
				jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
				int i;
				for (i = 0; i < keysize; i++) {
					bytes[i] = res[i];
				}

				// move from the temp structure to the java structure
				(*env)->SetByteArrayRegion(env, data, 0, keysize, bytes);
				return data;

			}
			jstring result = (*env)->NewStringUTF(env, res);
			return result;
			wrapper_aes_encrypt(id, (char *)elements, (int)num_bytes);
			return NULL;

		}
}
