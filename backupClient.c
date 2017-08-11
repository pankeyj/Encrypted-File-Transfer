/******************************************
 * CS457 TCP Programming
 * client.c
 * Purpose: Send files over a network
 * @author Jacob Pankey
********************************************/
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#define BUF_SIZE 256

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
			pthread_exit(0);
			open = 0;
			close(clientSocket);
			return;
		}
        }
}




int main(int argc, char** arg)
{
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
		send(sockfd, line, read, 0);		
		
	}
	free(line);
	close(sockfd);
	return 0;
}


