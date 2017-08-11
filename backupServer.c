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
#define BUF_SIZE 256



int main(int argc,char ** argv)
{
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
	printf("HELLO\n");
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
	printf("Goodbye\n");
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
		close(*(client->socket));
		free(client);
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
	while(1)
	{
		i = 0;
		memset(recvBuffer, '\0', BUF_SIZE);
		i = recv(clientSocket, recvBuffer, BUF_SIZE, 0 );
		printf("Size of buffer %d\n", i);
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
			else if( ! (strncmp(recvBuffer, "Kick", 4)) )
			{
				printf("Lets Kick somebody out\n");
				sscanf(recvBuffer + 5, "%d", &id);
				printf("Finna kick out %d\n", id);
				removeClient(id);
				pthread_exit(0);
			}
			else if( ! (strncmp(recvBuffer, "List", 4)) )
			{
				printf("Client wants a list :p\n");
				list(client);
			}
			else
			{
				printf("Probably a blank\n");
			}
		}
		else
		{
			printf("Nothing Recieved\n");
			removeClient(client->id);
		}
	}
}



