#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>




#ifndef _ENCRYPT_GAURD
#define _ENCRYPT_GAURD
void pthread_thread_id(
void handleErrors(void);
int rsa_encrypt(unsigned char*, size_t, EVP_PKEY, unsigned char*);
int rsa_decrypt(unsigned char*, size_t, EVP_PKEY, unsigned char*);
int decrypt(unsigned char*, int, unsigned char*,unsigned char*,unsigned char*);
void pthreads_locking_callback(int, int, const char, int);

#endif
