typedef struct client
{
	int id;
	int *socket;
	unsigned char symmetric_Key[32];	
	unsigned char iv[16];
	struct client *nextClient;
	struct client *prevClient;
}Client;

Client *head, *tail;
void printList();
void addClient(Client *newClient);
void removeClient(int id);
void recvMessage(Client *client);
