/***********************************
 * CS457 TCP Programming
 * server.c
 * Purpose: read file specified by client
 * and send data to the client
 * @author Jacob Pankey
************************************/
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "server.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h> 
//#include "encrypt.h"
#define BUF_SIZE 1024

EVP_PKEY *pubkey, *privkey;
unsigned char *pubfilename = "RSApub.pem";
unsigned char *privfilename = "RSApriv.pem";

void sendKey(Client*);
void thread_setup(void);
char* encryptMessage(unsigned char*);
unsigned char publicKey[32];
unsigned char iv[16];
void generateKeys();
int main(int argc,char ** argv)
{
	unsigned char key[32];
	unsigned char iv[16];

	// Set up OpenSSL
	thread_setup();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	generateKeys();


	/*Used for listening not communication*/
	int sockfd = socket(AF_INET,SOCK_STREAM,0);
	int port;
	printf("Which port would you like to listen to?\n");
	scanf("%d", &port);
	head = malloc(sizeof(Client));
	head->id = -1;		

	struct sockaddr_in serveraddr,clientaddr;
	serveraddr.sin_family=AF_INET;
	serveraddr.sin_port=htons(port);
	serveraddr.sin_addr.s_addr=INADDR_ANY;
	
	bind(sockfd,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
	listen(sockfd,10);
	
	int len = sizeof(clientaddr);

	int clientSocket, *new_sock;
	Client *newClient;
	// Each time a new client connnection is accepted
	// a new thread is created. This thread calls getFileName
	// The parent thread returns to wait for a new client to connect
	while((clientSocket = accept(sockfd, (struct sockaddr*) &clientaddr, &len)))
	{
		printf("Waiting to connect\n");	
		newClient = malloc(sizeof(Client));
		pthread_t child;
		new_sock = malloc(sizeof(new_sock));
		*new_sock = clientSocket;
		newClient->socket = new_sock;
		pthread_create(&child, NULL, (void*)addClient, newClient);
	}
	
	close(clientSocket);
	
	
	return 0;
}


void sendToClient(Client *client, char *msg)
{

	printf("Inside of sendtoclient\n");
	printf("Message: %s\n", msg);
	printf("Client ID %d\n", client->id);
	int clientSocket = *(client->socket);
	int length = strlen(msg);
	printf("Length of message: %d\n", length);
	send(clientSocket, msg,length, 0);
}

void addClient(Client *newClient)
{
	if(head->id == -1)
	{
		newClient->id = 0;
		head = newClient;
		tail = newClient;
	}
	else
	{
		tail->nextClient = newClient;
		newClient->prevClient = tail;
		newClient->id = tail->id + 1;
		tail = newClient;
	}
	recvMessage(newClient);
}


void list(Client *client)
{
	char list[BUF_SIZE];
	Client *tmpclient = head;
	while(tmpclient != tail)
	{
		printf("Looping\n");	
		printf("Next Client is %d\n", tmpclient->id);
		sprintf(list, "Client ID: %d is online\n", tmpclient->id);
		sendToClient(client, list);
		tmpclient = tmpclient->nextClient;
	}
	printf("Next Client is %d\n", tmpclient->id);
	sprintf(list, "Client ID: %d is online\n", tmpclient->id);
	sendToClient(client, list);
}
void removeClient(int id)
{
	Client *client = head;

	while(client->id != id)
		client = client->nextClient;
	if(client->id == id)
	{
		if(client == head)
		{
			client->nextClient->prevClient = NULL;
			head = client->nextClient;
		}else if(client == tail){
			client->prevClient->nextClient = NULL;
			tail = client->prevClient;
		}else{
			client->prevClient->nextClient = client->nextClient;
			client->nextClient->prevClient = client->prevClient;
		}
		printf("Almost finished\n");
		sendToClient(client, "EXIT");
		}else{
		printf("Unable to remove client %d\n", id);
	}

}

void sendToClientId(int id, char *msg)
{
	char num[5];
	sprintf(num, "%d", id);
	int length = strlen(num);
	printf("Length of number is: %d\n", length);
	msg = msg + strlen(num);

	Client *client = head;
	while(client->id != id)
		client = client->nextClient;
	if(client->id == id)
	{
		printf("Sending to id: %d\n", client->id);
		sendToClient(client, msg);
	}
	else
	{
		printf("This client does not exist\n");\
	}
}

void broadcast(char *msg)
{
	Client *client = head;
	while (client != tail)
	{
		sendToClient(client, msg);
		client = client->nextClient;
	}
	sendToClient(client, msg);
}


/******************************************
 * This function waits for the client to choose
 * the file that it wants sent by the server.
 * Once the server gets a file name it calls
 * send file to transfer the data
 * @param arg specifies the socket to read the
 * file name from
*******************************************/

void recvMessage(Client *client)
{
	char recvBuffer[BUF_SIZE];
	int clientSocket = *(client->socket);
	
	// This loops allows the client to continuously
	// request new files until the user types exit
	// to end the connection
	int i, id;
	memset(recvBuffer, '\0', BUF_SIZE);
	i = recv(clientSocket, recvBuffer, BUF_SIZE, 0);
	printf("The encrypted key is %s\n", recvBuffer);
	FILE* privf = fopen("RSApriv.pem", "rb");
	privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
	unsigned char decrypted_key[32];
	int decryptedkey_len = rsa_decrypt(recvBuffer, i, privkey,decrypted_key);
	printf("Length of decrypted key%d\n", decryptedkey_len);
	memcpy(client->symmetric_Key, decrypted_key, decryptedkey_len);
	printf("The decrypted random key %s\n", client->symmetric_Key);	
	i = recv(clientSocket, recvBuffer, 16, 0);
	memcpy(client->iv, recvBuffer, i);
	printf("This clients initialization vector %s\n", client->iv);
	
	unsigned char decryptedText[1024];

	while(1)
	{
		i = 0;
		memset(recvBuffer, '\0', BUF_SIZE);
		i = recv(clientSocket, recvBuffer, BUF_SIZE, 0 );
		printf("Size of buffer %d\n", i);	
		int length = decrypt(recvBuffer, strlen(recvBuffer), 256, privkey, client->symmetric_Key, client->iv););	
		if(i > 0)
		{
			printf("Received: %s\n", recvBuffer);
			if(! strncmp(recvBuffer, "SendTo", 6)) 
			{
				printf("Send to function received\n");
				sscanf(recvBuffer + 7, "%d", &id );
				printf("Send to client id:%d\n", id);
				sendToClientId(id, recvBuffer + 7);
			}
			else if( ! (strncmp(recvBuffer, "Broadcast", 9)) )
			{
				printf("Send Broadcast messsage\n");
				printf("Substring of Buffer: %s\n", recvBuffer + 10);
				broadcast(recvBuffer + 10);
			}
			else if( ! (strncmp(recvBuffer, "KickMe", 6)) )
			{
				printf("About to close the socket\n");
				close(client->socket);
                                free(client);
                                pthread_exit(NULL);
			}
			else if( ! (strncmp(recvBuffer, "List", 4)) )
			{
				printf("Client wants a list :p\n");
				list(client);
			}
			else if( ! (strncmp(recvBuffer, "Kick", 4)) )
			{
				printf("Lets Kick somebody out\n");
                                sscanf(recvBuffer + 5, "%d", &id);
                                printf("kick out %d\n", id);
                                removeClient(id);

			}
			else
			{
				printf("Unkown message type %s\n", recvBuffer);
			}
		}
		else
		{
			printf("Nothing Recieved\n");
			removeClient(client->id);
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
/*-
 *  *  *     if (CRYPTO_LOCK_SSL_CERT == type)
 *   *   *       BIO_printf(bio_err,"(t,m,f,l) %ld %d %s %d\n",
 *    *    *       CRYPTO_thread_id(),
 *     *     *       mode,file,line);
 *      *      */
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


char * encryptMessage(unsigned char *msg)
{
	printf("Going to encrypt a message\n");
        int cipehrtext_len;
        unsigned char ciphertext[1024];
        unsigned char encrypted_key[256];
	unsigned char key[32];
	unsigned char iv[16];
	int ciphertext_len;

        RAND_bytes(key,32);
        RAND_pseudo_bytes(iv,16);
        EVP_PKEY *pubkey, *privkey;
        FILE* pubf = fopen(pubfilename,"rb");
        pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
        int encryptedkey_len = rsa_encrypt(key, 32, pubkey, encrypted_key);
        ciphertext_len = encrypt (msg, strlen ((char *)msg), key, iv,
                            ciphertext);
        printf("Ciphertext is:\n");
        BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
        memcpy(msg, ciphertext, sizeof(ciphertext));
        return msg;
}

void generateKeys()
{
	FILE *pubf = fopen("RSApub.pem", "rb");
	pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
	FILE *privf = fopen("RSApriv.pem", "rb");
	privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
}


