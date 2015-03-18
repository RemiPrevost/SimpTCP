/*! \file client.c
 * \brief  A simple client in the internet domain using simpTCP
 *  The IP server name and its listening port number
 *  are passed as arguments 
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <simptcp_api.h>
#include <simptcp_entity.h>

/*!
 *  \def DEFAULT_LOCAL_UDP_PORT
 * \brief default udp port number used by simptcp protocol entity
 */
#define DEFAULT_LOCAL_UDP_PORT 15555

void error(char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    int sockfd;
    int portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;

    char buffer[256];

    if (argc < 3) {
        fprintf(stderr,"usage %s server_hostname server_port\n", argv[0]);
        exit(0);
    }

    printf("====== CLIENT =====\n\n");

    /* launch simptcp protocol entity */
    start_simptcp(DEFAULT_LOCAL_UDP_PORT);

    /* create a simptcp/IPv4 socket */
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SIMPTCP);
    if (sockfd < 0) 
        error("ERROR opening socket\n");
    /* create and fill the server's socket address */
    portno = atoi(argv[2]);
    server = gethostbyname(argv[1]);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,(char *)&serv_addr.sin_addr.s_addr,
            server->h_length);
    serv_addr.sin_port = htons(portno);

    /* connect to the server */
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) 
        error("ERROR connecting");

    /* read from stdin the message to send */
    printf("Please enter the message: ");  
    bzero(buffer,256);
    fgets(buffer,255,stdin);
    /* send the message */
    n = write(sockfd,buffer,strlen(buffer));
    if (n < 0) 
        error("ERROR writing to socket");

    /* close the socket */
    if (close(sockfd) == -1)
        error("ERROR closing client");

    printf("\nEnd of Client\n");

    return 0;
}
