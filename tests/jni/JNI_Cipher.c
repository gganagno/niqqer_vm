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
extern unsigned char *wrapper_aes_encrypt(int, unsigned char *, int);
extern char *wrapper_aes_decrypt(int, unsigned  char *, int);
extern unsigned char *wrapper_rsa_encrypt(int,  unsigned char *);
extern unsigned char *wrapper_rsa_decrypt(int,  unsigned char *);
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
    fprintf(stdout, "-------------------------------------------------------------\n\n\n");
    int i;
    unsigned char *res = NULL;
    int keysize = wrapper_rsa_get_key_size(id);
    jbyte* elements = (*env)->GetByteArrayElements(env, b, NULL);
    jsize num_bytes = (*env)->GetArrayLength(env, b);
    if (mode == 1) {

        if (algo == 1) {
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
        } else {
            fprintf(stdout, "AES Encryption\n");
            fprintf(stdout, "Input text: %s\n", elements);
            res = wrapper_aes_encrypt(id, (char *)elements, (int)num_bytes);
            fprintf(stdout, "\nEncrypted text\n\n");
            num_bytes = wrapper_aes_getbytes(id);
            for (i = 0; i < num_bytes; i++) {
                fprintf(stdout, "%u", res[i]);
            }
            fprintf(stdout, "\nEnd of Encrypted text\n\n");
            jbyteArray data = (*env)->NewByteArray(env, num_bytes);
            if (data == NULL) 
                return NULL; //  out of memory error thrown
            jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
            for (i = 0; i < num_bytes; i++)  {
                bytes[i] = res[i];
            }
            fprintf(stdout, "\n");
            (*env)->SetByteArrayRegion(env, data, 0, num_bytes, bytes);
            return data;
        }
    }else { 

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


            fprintf(stdout, "\nEncrypted text\n\n");
            num_bytes = wrapper_aes_getbytes(id);
            for (i = 0; i < num_bytes; i++) {
                fprintf(stdout, "%u", elements[i]);

            }
            fprintf(stdout, "\nEnd of Encrypted text\n\n");
            fprintf(stdout, "\nAES decryption\n");
            res = wrapper_aes_decrypt(id, (char *)elements, num_bytes);
            fprintf(stdout, "final result decrypt: |%s|\n", res);
            keysize = strlen((char *)res);
            jbyteArray data = (*env)->NewByteArray(env, keysize);
            if (data == NULL) {
                return NULL; //  out of memory error thrown
            }

            // creat bytes from byteUrl
            jbyte *bytes = (*env)->GetByteArrayElements(env, data, 0);
            for (i = 0; i < keysize; i++) {
                fprintf(stdout, "%u", elements[i]);
                bytes[i] = res[i];
            }
            fprintf(stdout, "\n");
            // move from the temp structure to the java structure
            (*env)->SetByteArrayRegion(env, data, 0, keysize, bytes);
            return data;
        }
    }
    jstring result = (*env)->NewStringUTF(env, res);
    return result;

}

