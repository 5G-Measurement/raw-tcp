#include "tcp.h"

// first it should connect to the server and then receive packets

int main(int argc,char **argv) {

    if (argc != 7)
	{
		printf("invalid parameters.\n");
		printf("USAGE %s <source-ip> <target-ip> <src-port> <target-port> <file-name> <duration>\n", argv[0]);
		return 1;
	}
	double timeToRun = strtod(argv[6], NULL);
	printf("%f\n", timeToRun);
    FILE *fptr;
    fptr = fopen(argv[5], "w");
    // exiting program 
    if (fptr == NULL) {
        printf("Error!");
        exit(1);
    };

	srand(time(NULL));

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock == -1)
	{
		printf("socket creation failed\n");
		return 1;
	}

	// destination IP address configuration
	struct sockaddr_in daddr;
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(atoi(argv[4]));
	if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1)
	{
		printf("destination IP configuration failed\n");
		return 1;
	}

	// source IP address configuration
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(atoi(argv[3])); // random client port
	if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1)
	{
		printf("source IP configuration failed\n");
		return 1;
	}
	
	printf("client listening on %u[%s], dest port is %u[%s]\n", saddr.sin_port, argv[3], daddr.sin_port, argv[4]);

	// tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
	{
		printf("setsockopt(IP_HDRINCL, 1) failed\n");
		return 1;
	}

	// send SYN
	char* packet;
	int packet_len;
	create_syn_packet(&saddr, &daddr, &packet, &packet_len);
    // char request[] = "Hello there!";
	// create_data_packet(&saddr, &daddr, 345, 765, request, sizeof(request) - 1/sizeof(char), &packet, &packet_len);
	int startPkts = 5;
	while (startPkts > 0) {
		int sent;
		if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
		{
			printf("sendto() failed\n");
		}
		else
		{
			printf("successfully sent %d bytes SYN to %u from %u\n", sent, daddr.sin_port, saddr.sin_port);
		}
		startPkts--;
	}
	

    unsigned short d_port;
	int received = 0;
    char recvbuf[DATAGRAM_LEN];
    char clientip[INET_ADDRSTRLEN];

    printf("client receiving data on port %u\n", saddr.sin_port);

	struct timeval startTime;
	struct timeval currentTime;
	double relativeTime=0;
	
	gettimeofday(&startTime,NULL);
	fprintf(fptr, "time, size\n");
    
	while (relativeTime <= timeToRun) {
		int r_size = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
		gettimeofday(&currentTime);
		relativeTime = (currentTime.tv_sec-startTime.tv_sec)+(currentTime.tv_usec-startTime.tv_usec)/1000000.0;
		fprintf(fptr, "%f, %d\n", relativeTime, r_size);
	}
	
    fclose(fptr);
    printf("Client exiting \n");
    close(sock);
    return 0;
}