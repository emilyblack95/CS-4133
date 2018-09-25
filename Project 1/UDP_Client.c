/*
 * UDP_Client.c
 *
 * Created on: Sep 2, 2018
 * Author: emilyblack95
 *
 * API: https://www.tcpdump.org/manpages/pcap.3pcap.html
 * Resource: http://www.tcpdump.org/sniffex.c
 * Resource: http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

/* port num */
#define PORT 8080

/* max size of buffer */
#define MAXLINE 1024

/* Driver */
int main(int argc, char *argv[]) {
	pcap_t *pcap; /* pcap file */
	int sock, n; /* socket file descriptor */
	int count = 1;
	socklen_t len; /* holds size of server addr */

	char buffer[MAXLINE];
	char errbuffer[PCAP_ERRBUF_SIZE];
	char *hello = "The client says hello.";

	struct sockaddr_in servaddr; /* server address */
	struct pcap_pkthdr header; /* The packet header */
	const u_char *packet;

	/* Skip over the program name. */
	++argv; --argc;

	/* If the name of the pcap file doesn't exist on the payload */
	if(argc != 1) {
		printf("%s\n", "Error: Program requires 1 argument but received no arguments.");
		return 1;
	}

	/* Create socket */
	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("\nError: File descriptor not received.\n");
		exit(EXIT_FAILURE);
	}

	/* Set value of servaddr */
	memset(&servaddr, 0, sizeof(servaddr));

	/* Filling server info */
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	servaddr.sin_addr.s_addr = INADDR_ANY;

	len = sizeof(servaddr);

	/* send hello to server */
	sendto(sock, (const char *)hello, strlen(hello), 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));

	printf("%s\n", "Success: Hello message sent.");

	/* receive message, return length of message in bytes */
	n = recvfrom(sock, (char *)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &servaddr, &len);
	buffer[n] = '\0'; // null

	printf("Server: %s\n", buffer);

	/* Get pcap file from argv, open it */
	pcap = pcap_open_offline(argv[0], errbuffer);

	if(pcap == NULL) {
		printf("%s\n", "Error: Error reading PCAP file.");
		return 1;
	}

	/* Now just loop through extracting packets as long as we have some to read. */
	while ((packet = pcap_next(pcap, &header)) != NULL) {
		sendto(sock, (char *)packet, header.len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
		printf("Success: Packet #%d sent.\n", count);
		count++;
	}

	pcap_close(pcap);
	close(sock);
	return 0;
}
