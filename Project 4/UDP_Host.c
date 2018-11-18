/*
 * UDP_Host.c
 * Similar to project 3, but instead of flooding
 * the program/hosts utilize routing tables.
 *
 * Created on: Nov 14, 2018
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
 #include <pcap.h>
 #include <pthread.h>

 //Hashtable class
 #include "strmap.h"
 #include "strmap.c"

 #define MAXLINE 1024
 #define SNAP_LEN 1518
 #define SIZE_ETHERNET 16 /*use to be 14 */
 #define ETHER_ADDR_LEN 8
 #define foreach(item, array) \
     for(int keep = 1, \
             count = 0,\
             size = sizeof (array) / sizeof *(array); \
         keep && count != size; \
         keep = !keep, count++) \
       for(item = (array) + count; keep; keep = !keep)

 /* Ethernet header */
 /* Source: http://www.tcpdump.org/sniffex.c */
 struct sniff_ethernet {
   u_char ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
   u_char ether_shost[ETHER_ADDR_LEN];    /* source host address */
   u_short ether_type;                     /* IP? ARP? RARP? etc */
 };

 /* IP header */
 /* Source: http://www.tcpdump.org/sniffex.c */
 struct sniff_ip {
   u_char ip_vhl;                 /* version << 4 | header length >> 2 */
   u_char ip_tos;                 /* type of service */
   u_short ip_len;                 /* total length */
   u_short ip_id;                  /* identification */
   u_short ip_off;                 /* fragment offset field */
   #define IP_RF 0x8000            /* reserved fragment flag */
   #define IP_DF 0x4000            /* dont fragment flag */
   #define IP_MF 0x2000            /* more fragments flag */
   #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
   u_char ip_ttl;                 /* time to live */
   u_char ip_p;                   /* protocol */
   u_short ip_sum;                 /* checksum */
   struct in_addr ip_src,ip_dst;  /* source and dest address */
 };
 #define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
 #define IP_V(ip)                (((ip)->ip_vhl) >> 4)

 /* Defines structure of each neighbor/host */
 typedef struct {
   char real_ip[10]; /* typically 127.0.0.1 */
   char fake_ip[9]; /* 10.0.0... */
   int port;
 } host;

 /* Defines structure of data that needs to be passed
  * to send func */
 typedef struct {
   char *pcapName; /* name of pcap file. double pointer due to argv */
   char *hostTxtFile; /* text file passed into program */
 } sendData;

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
  * Function to send frames from other hosts.
  * Only sends if packet source IP is same as host IP.
  */
 void * sendFunc(void *vargp) {
   sleep(10);
   /* Variables */
   /* read in pcap file passed in as threads argument */
   sendData *data = (sendData *)vargp;
   char *pcapName = data->pcapName;
   char *fileName = data->hostTxtFile;
   host thisHost;
   FILE * fp;
   char line[256];
   char fake_host_ip[256];
   int port;
   int numOfNeighbors;
   int counter = 0;

   const int optVal = 1;
   pcap_t *pcap;
   struct pcap_pkthdr *header;
   char errbuffer[PCAP_ERRBUF_SIZE];
   const u_char *packet = NULL;
 	 const struct sniff_ip *ip = NULL; /* The IP header */
   const char *payload = NULL; /* Packet payload */
   struct sockaddr_in servaddr; /* server address */
   struct sniff_ethernet *ethernet;
   int sock;
   int size_ip;
   int size_payload;
   int count = 1;

   fp = fopen(fileName, "r");

   if(fp == NULL) {
     exit(EXIT_FAILURE);
   }

   printf("%s\n", "Getting host info...");
   /* Get real host ip */
   /* Don't store blank lines */
   fgets(fake_host_ip, sizeof(fake_host_ip), fp);
   while(fake_host_ip[0] == '\n') {
     fgets(fake_host_ip, sizeof(fake_host_ip), fp);
   }
   printf("Fake host IP: %s", fake_host_ip);

   strncpy(thisHost.fake_ip, fake_host_ip, 9);
   strncpy(thisHost.real_ip, "127.0.0.1", 10);

   /* Get port */
   /* Don't store blank lines */
   fgets(line, sizeof(line), fp);
   while(line[0] == '\n') {
     fgets(line, sizeof(line), fp);
   }
   /* Convert string to int */
   port = atoi(line);
   printf("Port: %d\n", port);
   thisHost.port = port;
   /* empty string */
   line[0] = '\0';

   /* Get number of neighbors */
   fgets(line, sizeof(line), fp);
   /* Don't store blank lines */
   while(line[0] == '\n') {
     fgets(line, sizeof(line), fp);
   }
   /* Convert string to int */
   numOfNeighbors = atoi(line);
   printf("Number of Neighbors: %d\n", numOfNeighbors);
   /* empty string */
   line[0] = '\0';

   /* declare neighbor list */
   host hostList[numOfNeighbors];

   /* while we still have neighbors to add, parse the line into a neighbor
    * and add it to the neighborList */
   printf("%s\n", "Neighbors:");
   while(counter < numOfNeighbors) {

     line[0] = '\0';
     /* Get line */
     fgets(line, sizeof(line), fp);
     /* Don't store blank lines */
     while(line[0] == '\n') {
       fgets(line, sizeof(line), fp);
     }

     /* parse line by space */
     strncpy(hostList[counter].fake_ip, strtok(line, " "), 9);
     strncpy(hostList[counter].real_ip, strtok(NULL, " "), 10);
     hostList[counter].port = atoi(strtok(NULL, " "));

     printf("%s, %s, %d\n", hostList[counter].fake_ip, hostList[counter].real_ip, hostList[counter].port);
     counter++;
   }
   fclose(fp);

   /* Get pcap file from argv, open it */
   pcap = pcap_open_offline(pcapName, errbuffer);

   if(pcap == NULL) {
     printf("%s\n", "Error: Error reading PCAP file.");
     exit(EXIT_FAILURE);
   }

   printf("%s\n", "Trying to send packets...");
   /* While there are some packets to read, get the source IP */
 	while (pcap_next_ex(pcap, &header, &packet) != -2) {
     /* if we DIDN'T received an ARP packet */
     if(header->len > 44) {
       /* define ethernet header */
     	 ethernet = (struct sniff_ethernet*)(packet);
       /* define/compute ip header offset */
       ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
       size_ip = (IP_HL(ip)*4);
       if (size_ip < 20) {
         break;
       }

       char *pos;
       if ((pos=strchr(thisHost.fake_ip, '\n')) != NULL) {
         *pos = '\0';
       }

       /* because strings are null terminated, must only compare first 9 chars */
       if(strcmp(inet_ntoa(ip->ip_src), thisHost.fake_ip) == 0) {
         printf("Success: Host IP matches Source IP: %s\n", inet_ntoa(ip->ip_src));
         /* Create socket */
       	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
       		perror("\nError: File descriptor not received.\n");
       		exit(EXIT_FAILURE);
       	}

       	/* Set value of servaddr */
       	memset(&servaddr, 0, sizeof(servaddr));
         servaddr.sin_family = AF_INET;
         servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

         foreach(host *n, hostList) {
           servaddr.sin_port = n->port;
           bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));
           sendto(sock, (char *)packet, header->len, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
           printf("Success: Sent to neighbor: %s, %d\n", n->fake_ip, n->port);
         }
         printf("Success: Sent packet #%d to neighbors.\n", count);
         count++;
       }
   	}
   }
   printf("%s\n", "Done sending packets...");
   printf("%s\n", "Now waiting for incoming packets...");
   return NULL;
 }

 /*
  * Function to receive frames from other hosts.
  * Only parse and print if packet dest IP is same as host IP.
  */
 void * receiveFunc(void *vargp) {
   /* Variables */
   /* read in pcap file passed in as threads argument */
   sendData *data = (sendData *)vargp;
   char *fileName = data->hostTxtFile;
   host thisHost;
   FILE * fp;
   char line[256];
   char fake_host_ip[256];
   int port;
   int numOfNeighbors;
   int counter = 0;

   const int optVal = 1;
   int sock, n, nsock;
   socklen_t len;
   u_char packet[MAXLINE];
   struct pcap_pkthdr header;
   struct sockaddr_in servaddr; /* server address */
   struct sockaddr_in cliaddr; /* client address */
   char hostBuffer[MAXLINE];
   /* declare pointers to packet headers */
 	 struct sniff_ethernet *ethernet;
 	 const struct sniff_ip *ip; /* The IP header */
   const char *payload; /* Packet payload */
 	 int size_ip;
   int size_payload;
   int count = 1;

   fp = fopen(fileName, "r");

   if(fp == NULL) {
     exit(EXIT_FAILURE);
   }

   /* Get real host ip */
   /* Don't store blank lines */
   fgets(fake_host_ip, sizeof(fake_host_ip), fp);
   while(fake_host_ip[0] == '\n') {
     fgets(fake_host_ip, sizeof(fake_host_ip), fp);
   }

   strncpy(thisHost.fake_ip, fake_host_ip, 9);
   strncpy(thisHost.real_ip, "127.0.0.1", 10);

   /* Get port */
   /* Don't store blank lines */
   fgets(line, sizeof(line), fp);
   while(line[0] == '\n') {
     fgets(line, sizeof(line), fp);
   }
   /* Convert string to int */
   port = atoi(line);
   thisHost.port = port;
   /* empty string */
   line[0] = '\0';

   /* Get number of neighbors */
   fgets(line, sizeof(line), fp);
   /* Don't store blank lines */
   while(line[0] == '\n') {
     fgets(line, sizeof(line), fp);
   }
   /* Convert string to int */
   numOfNeighbors = atoi(line);
   /* empty string */
   line[0] = '\0';

   /* declare neighbor list */
   host hostList[numOfNeighbors];

   /* while we still have neighbors to add, parse the line into a neighbor
    * and add it to the neighborList */
   while(counter < numOfNeighbors) {

     line[0] = '\0';
     /* Get line */
     fgets(line, sizeof(line), fp);
     /* Don't store blank lines */
     while(line[0] == '\n') {
       fgets(line, sizeof(line), fp);
     }

     /* parse line by space */
     strncpy(hostList[counter].fake_ip, strtok(line, " "), 9);
     strncpy(hostList[counter].real_ip, strtok(NULL, " "), 10);
     hostList[counter].port = atoi(strtok(NULL, " "));

     counter++;
   }
   fclose(fp);

   /* Create socket */
 	if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
 		perror("\nError: File descriptor not received.\n");
 		exit(EXIT_FAILURE);
 	}

   /* Create socket */
 	if((nsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
 		perror("\nError: File descriptor not received.\n");
 		exit(EXIT_FAILURE);
 	}

   /* Set value of servaddr/cliaddr */
   memset(&servaddr, 0, sizeof(servaddr));
   memset(&cliaddr, 0, sizeof(cliaddr));

   /* Filling server info, bind to any address/port */
 	servaddr.sin_family = AF_INET; // IPv4
 	servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
 	servaddr.sin_port = thisHost.port;

 	/* Bind the socket with the server addr */
 	if(bind(sock, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
 		printf("Info: Socket already bound with server address.\n");
 	}

   len = sizeof(servaddr);

   /* infinite while loop */
   printf("%s\n", "Listening for packets...");
   while(1) {
     /* receive packet from client, return length of message in bytes */
     n = recvfrom(sock, (u_char *)packet, MAXLINE, MSG_WAITALL, (struct sockaddr *) &cliaddr, &len);
     if(n > 0) {
       packet[n] = '\0'; // null

     	/* define ethernet header */
     	ethernet = (struct sniff_ethernet*)(packet);

     	/* define/compute ip header offset */
     	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
     	size_ip = IP_HL(ip)*4;
     	if (size_ip < 20) {
     		break;
     	}
       printf("Received packet with source: %s\n", inet_ntoa(ip->ip_src));

       char *pos;
       if ((pos=strchr(thisHost.fake_ip, '\n')) != NULL) {
         *pos = '\0';
       }

       /* if the destination ip matches the fake ip, print the packet */
       if(strcmp(inet_ntoa(ip->ip_dst), thisHost.fake_ip) == 0) {
         printf("Packet #: %d\n", count);
         /* print ether Linux Cooked Packet data */
         printf("------ LCP/Ether Header ------\n");
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
         printf(" Source Address: %s\n", inet_ntoa(ip->ip_src));
         printf(" Destination Address: %s\n", inet_ntoa(ip->ip_dst));

         /* define/compute payload (segment) offset */
         payload = (char *)(packet + SIZE_ETHERNET + size_ip);

         /* compute payload (segment) size */
         size_payload = ntohs(ip->ip_len) - (size_ip);

         /*
          * Print payload data; it might be binary, so don't just
          * treat it as a string.
          */
         if (size_payload > 0) {
           printf("Payload (%d bytes):\n", size_payload);
           print_payload((const u_char *)payload, size_payload);
         }
         count++;
       }
       /* else check routing table and re-route packet */
       else {
         //TODO: finish this
         //TODO: make routing table in receive func
         packet[n] = '\0'; // null
         printf("Packet destination doesn't match host IP, initializing routing algorithm...\n");
         //check if destination is a key in the hashtable, find where to route it to
           foreach(host *neighbor, hostList) {
             //if the destination is a key, route it
             if(strcmp(inet_ntoa(ip->ip_src), neighbor->fake_ip) != 0) {
               printf("Packet is being routed to: %s, %d\n", sourceIP, port);
               /* Set value of servaddr */
             	servaddr.sin_port = neighbor->port;
               bind(nsock, (struct sockaddr *)&servaddr, sizeof(servaddr));
               printf("Success: Sent to neighbor: %s, %d\n", neighbor->fake_ip, servaddr.sin_port);
               sendto(nsock, (const char *)packet, n, 0, (const struct sockaddr *) &servaddr, sizeof(servaddr));
             }
           }
           printf("Done running routing algorithm.\n");
         }
       }
     }
   }
   return NULL;
 }

 /* Driver */
 int main(int argc, char *argv[]) {
   /* Threads */
   pthread_t receive_thread;
   pthread_t send_thread;
   sendData dataForSendFunc; //for sending

   /* Skip over the program name. */
 	++argv; --argc;

   /* If the name of the host info file doesn't exist on the payload */
 	if(argc == 0) {
 		printf("%s\n", "Error: Program requires 2 arguments but received 0 arguments.");
 		exit(EXIT_FAILURE);
 	}
   else {
     dataForSendFunc.hostTxtFile = argv[0];
   }
   /* Skip over host info file. */
 	++argv; --argc;

   /* If the program is/isn't being passed a pcap file */
 	if(argc != 1) {
 		printf("%s\n", "Error: Program received no PCAP file.");
     exit(EXIT_FAILURE);
 	}
   else {
     dataForSendFunc.pcapName = argv[0];
     pthread_create(&receive_thread, NULL, receiveFunc, &dataForSendFunc);
     pthread_create(&send_thread, NULL, sendFunc, &dataForSendFunc);
     pthread_join(send_thread, NULL);
     pthread_join(receive_thread, NULL);
   }
 	return 0;
 }
