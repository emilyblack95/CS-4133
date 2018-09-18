/*
 * UDP_Server.c
 *
 * Created on: Sep 2, 2018
 * Author: emilyblack95
 *
 * API: https://www.tcpdump.org/manpages/pcap.3pcap.html
 * Resource: http://www.tcpdump.org/sniffex.c
 * Resource: http://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <ctype.h>
#include <netinet/if_ether.h>
#include "./pcap.h"

/* port num */
#define PORT 8080

/* max size of buffer */
#define MAXLINE 1024

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
/* Source: http://www.tcpdump.org/sniffex.c */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
/* Source: http://www.tcpdump.org/sniffex.c */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 * Source: http://www.tcpdump.org/sniffex.c
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if(i == 7) {
			printf(" ");
    }
	}
	/* print space to handle line less than 8 bytes */
	if(len < 8) {
		printf(" ");
	}
	/* fill hex gap with spaces if not full line */
	if(len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch)) {
			printf("%c", *ch);
    }
		else {
			printf(".");
    }
		ch++;
	}

	printf("\n");
  return;
}

/*
 * print packet payload data (avoid printing binary data)
 * Source: http://www.tcpdump.org/sniffex.c
 */
void print_payload(const u_char *payload, int len) {
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if(len <= 0) {
		return;
  }
	/* data fits on one line */
	if(len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
  return;
}

/*
 * Parses the packet and prints its data.
 * Source: http://www.tcpdump.org/sniffex.c
 */
void parsePacket(int len, const u_char *packet, socklen_t slen) {
	static int count = 1; /* packet counter */
  char hostBuffer[MAXLINE];

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip; /* The IP header */
  const char *payload; /* Packet payload */

	int size_ip;
  int size_payload;

	printf("\nPacket #%d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print ether header data */
	printf("------ Ether Header ------\n");
	printf(" Packet Size: %d bytes\n", len); /* len of entire packet */
	printf(" Source: %02X-%02X-%02X-%02X-%02X-%02X\n", ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2],
	ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
	printf(" Destination: %02X-%02X-%02X-%02X-%02X-%02X\n", ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2],
	ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
	printf(" Ethertype: %hu\n", ntohs(ethernet->ether_type));

	/* print ip header data */
	printf("------ IP Header ------\n");
	printf(" Version: %d\n", IP_V(ip));
	printf(" Header length: %d bytes\n", IP_HL(ip)*IP_V(ip)); /* len of just this header */
	printf(" Type of Service: %d\n", ip->ip_tos);
	printf(" Total Length: %hu octets\n", ntohs(ip->ip_len));
	printf(" Identification: %d\n", ntohs(ip->ip_id));
	printf(" Fragment Offset: %d bytes\n", ntohs(ip->ip_off)); //Gives correct value, check https://stackoverflow.com/questions/2307531/error-parsing-ip-header
	printf(" Time to Live: %hhu seconds/hops\n", ip->ip_ttl);
	printf(" Protocol: %hhu\n", ip->ip_p);
	printf(" Header Checksum: %.4x\n", ntohs(ip->ip_sum));
  printf(" Source Address: %s, %s\n", inet_ntoa(ip->ip_src), "localhost"); //not sure how to NOT hardcode this yet
  printf(" Destination Address: %s, %s\n", inet_ntoa(ip->ip_dst), "localhost"); //not sure how to NOT hardcode this yet

  /* define/compute payload (segment) offset */
	payload = (char *)(packet + SIZE_ETHERNET + size_ip);

	/* compute payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip);

	/*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	if (size_payload > 0) {
		printf(" Payload (%d bytes):\n", size_payload);
		print_payload((const u_char *)payload, size_payload);
	}

	return;
}

/* Driver */
int main() {
	u_char packet[MAXLINE]; /* packet received from client */
	int sock, n; /* socket file descriptor */
	socklen_t len; /* holds size of server addr */

	char buffer[MAXLINE];
	char errbuffer[PCAP_ERRBUF_SIZE];
	char *hello = "The server says hello.";

	struct sockaddr_in servaddr; /* server address */
	struct sockaddr_in cliaddr; /* client address */

	/* Create socket */
	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("\nError: File descriptor not received.\n");
		exit(EXIT_FAILURE);
	}

	/* Set value of servaddr/cliaddr */
	memset(&servaddr, 0, sizeof(servaddr));
	memset(&cliaddr, 0, sizeof(cliaddr));

	/* Filling server info */
	servaddr.sin_family = AF_INET; // IPv4
	servaddr.sin_addr.s_addr = INADDR_ANY;
	servaddr.sin_port = htons(PORT);

	/* Bind the socket with the server addr */
	if(bind(sock, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		perror("\nError: Failed to bind socket with the server address.\n");
		exit(EXIT_FAILURE);
	}

	len = sizeof(servaddr);

	/* receive message from client, return length of message in bytes */
	n = recvfrom(sock, (char *)buffer, MAXLINE, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
	buffer[n] = '\0'; // null

	printf("Client: %s\n", buffer);

	/* send hello to client */
	sendto(sock, (const char *)hello, strlen(hello), 0, (const struct sockaddr *) &cliaddr, len);

	printf("Success: Hello message sent.\n");

	/* receive packet from client, return length of message in bytes */
	n = recvfrom(sock, (u_char *)packet, MAXLINE, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
	packet[n] = '\0'; // null
	parsePacket(n, packet, len);

  /* receive packet from client, return length of message in bytes */
	n = recvfrom(sock, (u_char *)packet, MAXLINE, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
	packet[n] = '\0'; // null
	parsePacket(n, packet, len);

	close(sock);
	return 0;
}
