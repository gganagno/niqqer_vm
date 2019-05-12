#include <stdio.h>      /* vsnprintf */
#include <stdarg.h>

#include "TestEnclave.h"
#include "TestEnclave_t.h"  /* print_string */
#include "tSgxSSL_api.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#define fprintf(a, ...) printf(__VA_ARGS__)
//#define KEY_LENGTH  2048
#define PUB_EXP     3
#define PRINT_KEYS



struct rsa_key_t{
    RSA *keypair;
    char *pubkey;
    char *privkey;
    short enc_len;
}rsa_key;

struct aes_key_t {
    unsigned char *key;
    int enc_len;
};

/* 100 keys of 16 byte len */
struct key_array_t {
    short size;
    short type;
    union key_type {
        struct aes_key_t key;// char *key;

        struct rsa_key_t rk;
    }kt;

};


struct key_array_t key_array[100];
int active_ids = 0;

    char *
strdup (char *s)
{
    char *t;
    t = (char *)calloc(strlen(s) + 1, sizeof(char));
    memcpy(t, s, strlen(s));
    return t;
}


void
print_key(int id){
    print_data((char *)key_array[id].kt.key.key, key_array[id].size);
}

    void
get_key(int id, char *got, int size)
{

    memcpy(got, key_array[id].kt.key.key, size);
    //got = key_array[id];
}

void
aes_encrypt(int id, unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    int size = key_array[id].size;	

    //unsigned char *ciphertext;
    EVP_CIPHER_CTX *ctx;
    unsigned char *iv = NULL;
    //ciphertext = (unsigned char *)calloc(plaintext_len, sizeof(unsigned char));
    int len;

    unsigned char *key = key_array[id].kt.key.key;
    int ciphertext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        printf("CTX ERROR\n");

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) == 0)
        printf("Encrypt Error\n");

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, plaintext_len) == 0)
        printf("Encrypt update error\n");
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) == 0)
        printf("Encrypt update error\n");
    ciphertext_len += len;
    key_array[id].kt.key.enc_len = ciphertext_len;
    
    //aes_decrypt(id, (char *)ciphertext, ciphertext_len, lol);
    //printf("-----\n\n%s\n\n", lol);
    
    //return ciphertext;

}

void
aes_decrypt(int id, unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) 
{

    ciphertext_len = key_array[id].kt.key.enc_len;
    
    unsigned char *key = key_array[id].kt.key.key;
    unsigned char *iv = NULL;

    int len;

    // printf("ciphertexlen : %d\n",ciphertext_len);
    EVP_CIPHER_CTX *ctx;
    int plaintext_len;
    
    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();
    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (ciphertext == NULL || plaintext == NULL)
        abort();
    EVP_DecryptUpdate(ctx, (unsigned char *)plaintext, &len, (unsigned char *)ciphertext, ciphertext_len);
    plaintext_len = len;
    // printf("plaintext_len : %d\n", plaintext_len);
    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */

    EVP_DecryptFinal_ex(ctx, (unsigned char *)plaintext + len, &len);
    plaintext_len += len;
    // printf("plaintext_len : %d\n", plaintext_len);
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    plaintext[plaintext_len]='\0';

}




int
keygen(int size){
    key_array[active_ids].kt.key.key = (unsigned char *)calloc(size, sizeof(unsigned char));
    key_array[active_ids].size = size;
    RAND_bytes(key_array[active_ids].kt.key.key, size);
    key_array[active_ids].kt.key.key[size -1] = '\0';

    //print_data((char *)key_array[active_ids].kt.key.key, size);
    return active_ids++;
}










/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}

typedef void CRYPTO_RWLOCK;

struct evp_pkey_st {
    int type;
    int save_type;
    int references;
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *engine;
    union {
        char *ptr;
# ifndef OPENSSL_NO_RSA
        struct rsa_st *rsa;     /* RSA */
# endif
# ifndef OPENSSL_NO_DSA
        struct dsa_st *dsa;     /* DSA */
# endif
# ifndef OPENSSL_NO_DH
        struct dh_st *dh;       /* DH */
# endif
# ifndef OPENSSL_NO_EC
        struct ec_key_st *ec;   /* ECC */
# endif
    } pkey;
    int save_parameters;
    STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
    CRYPTO_RWLOCK *lock;
} /* EVP_PKEY */ ;









int vprintf_cb(Stream_t stream, const char * fmt, va_list arg)
{
    char buf[BUFSIZ] = {'\0'};

    int res = vsnprintf(buf, BUFSIZ, fmt, arg);
    if (res >=0) {
        sgx_status_t sgx_ret = uprint((const char *) buf);
        TEST_CHECK(sgx_ret);
    }
    return res;
}






    int 
m(int KEY_LENGTH)
{
    size_t pri_len;            // Length of private key
    size_t pub_len;            // Length of public key
    char   *pri_key;           // Private key
    char   *pub_key;           // Public key
    // Generate key pair
    //printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
    key_array[active_ids].kt.rk.keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);
    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());
    key_array[active_ids].size = KEY_LENGTH;
    PEM_write_bio_RSAPrivateKey(pri, key_array[active_ids].kt.rk.keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub,  key_array[active_ids].kt.rk.keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    pri_key = (char *)calloc(1, pri_len + 1);

    pub_key = (char *)calloc(1, pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    key_array[active_ids].kt.rk.privkey = strdup(pri_key);
    key_array[active_ids].kt.rk.pubkey = strdup(pub_key);

    return active_ids++;
}


int rsa_get_key_size(int id)
{

    return key_array[id].size;

}
void rsa_encrypt(int id, unsigned char *msg, unsigned char *encrypt) {
    char *err;

    // Encrypt the message
    //encrypt = (unsigned char *)calloc(RSA_size(key_array[id].kt.rk.keypair), sizeof(unsigned char));
    int encrypt_len;
    err = (char *)calloc(1, 130);
    if((encrypt_len = RSA_public_encrypt(strlen((char *)msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
                    key_array[id].kt.rk.keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
    }
    key_array[id].kt.rk.enc_len = encrypt_len; 
}

void rsa_decrypt(int id, unsigned char *encrypt, unsigned char *decrypt) {
    char *err = (char *)calloc(1, 130);
    int encrypt_len = key_array[id].kt.rk.enc_len;
    // Decrypt it
    // printf("Encrypt len %d\n", encrypt_len);
    if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
                key_array[id].kt.rk.keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    }

    decrypt[encrypt_len] = '\0';
    // printf("Decrypted message: ->|%s|\n", decrypt);
    // return decrypt;
}

void 
get_pubkey(int id, char *r)
{
    memcpy(r, key_array[id].kt.rk.pubkey, key_array[id].size);
}

void
get_privkey(int id, char *r)
{


    memcpy(r, key_array[id].kt.rk.privkey, key_array[id].size);
    //return key_array[id].kt.rk.privkey;
}


    void
startup()
{
    SGXSSLSetPrintToStdoutStderrCB(vprintf_cb);
    // Initialize SGXSSL crypto
    OPENSSL_init_crypto(0, NULL);

}

    int
generate_keypair(int size)
{
    int id;
    id = m(size);
    return id;
}

    int
aes_getbytes(int id)
{
    return key_array[id].kt.key.enc_len;
}
