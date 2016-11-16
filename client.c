/******************************************
 * CS457 TCP Programming
 * client.c
 * Purpose: Secure Chat Communications
 * @author Jacob Pankey
********************************************/
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#define BUF_SIZE 1024
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>



unsigned char key[32], publicKey[32], iv[16];
static int open = 1;
void recvMessages(void *arg)
{
        char buf[BUF_SIZE];
        int clientSocket = *(int*)arg;
        while(1)
        {
                printf("Waiting to receive\n");
                memset(buf, '\0', BUF_SIZE);
                int i = recv(clientSocket, buf, BUF_SIZE, 0);
                printf("Received from server %s\n", buf);
				

		if(strcmp(buf, "EXIT") == 0)
		{
			send(clientSocket, "KickMe", 6, 0);
			close(clientSocket);
			open = 0;
			pthread_exit(NULL);
			return;
		}
        }
}


static pthread_mutex_t *lock_cs;
static long *lock_count;


void pthreads_thread_id(CRYPTO_THREADID *tid)
{
    CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}


void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
# ifdef undef
    BIO_printf(bio_err, "thread=%4d mode=%s lock=%s %s:%d\n",
               CRYPTO_thread_id(),
               (mode & CRYPTO_LOCK) ? "l" : "u",
               (type & CRYPTO_READ) ? "r" : "w", file, line);
# endif
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

void thread_setup(void)
{
    int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_THREADID_set_callback(pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
}



void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}


int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){ 
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}


int main(int argc, char** arg)
{

	  unsigned char *pubfilename = "RSApub.pem";


	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	
	if(sockfd < 0)
	{
		printf("There was an error creating the socket\n");
		return 1;
	}

	int port;
	char ip[5000];
	printf("Which port?\n");
	scanf("%d", &port);
	printf("Which IP?\n");
	scanf("%s", &ip);

	struct sockaddr_in serveraddr;
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(port);
	serveraddr.sin_addr.s_addr = inet_addr(ip);
	
	int e = connect(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
	if (e < 0 )
	{
		printf("Error connecting\n");
		return 1;
	}
	int *new_sock;
	new_sock = malloc(sizeof(new_sock));
	*new_sock = sockfd;
	pthread_t child;
	// Generate Random key
	RAND_bytes(key,32);
        RAND_pseudo_bytes(iv,16);
	
	printf("Randomly Generated Key %s\n", key);
	printf("Randomly generate iv %s\n", iv);
	//Read the public key and use it to encrypt the random key
        EVP_PKEY *pubkey, *privkey;
        FILE* pubf = fopen(pubfilename,"rb");
        pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
        unsigned char encrypted_key[256];
        int encryptedkey_len = rsa_encrypt(key, 32, pubkey, encrypted_key);	
	//Send the encrpyted key to server
	printf("Encrypted key len %d\n", encryptedkey_len);
	send(sockfd, encrypted_key, encryptedkey_len, 0);
	char buf[256];
	sprintf(buf, "%s", iv);
	send(sockfd, buf, 256, 0);
	printf("Clients versions of encrypted key %s\n", encrypted_key);


	pthread_create(&child, NULL, recvMessages, (void*) new_sock);


	

	char recvBuffer[BUF_SIZE];
	char *line = NULL;
	int read;
	size_t len = 0;
	// Client continuously loops to accept a new file
	// after the first finishes writing
	while(open)
	{
		printf("Commands:\n\t Broadcast msg\n\t SendTo 'ID' msg\n\tKick 'ID'\n\t ListClients\n");
		line = NULL;
		len = 0;
		read = getline(&line, &len, stdin);
		unsigned char encryptedText[1024];
		// Encrypt line here
		int j = encrypt(line, strlen((char*)line), key, iv, encryptedText);		


		send(sockfd, encryptedText, j, 0);		
		
	}
	free(line);
	close(sockfd);
	return 0;
}


