#include "tcp.h"

int main(int argc, char** argv)
{
	if (argc != 4)
	{
		printf("invalid parameters.\n");
		printf("USAGE %s <listen-port> <send-port> <duration>\n", argv[0]);
		return 1;
	}
	double timeToRun = strtod(argv[3], NULL) + 1.0; // stop a little after the receiver finishes
	srand(time(NULL));

	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock == -1)
	{
		printf("socket creation failed\n");
		return 1;
	}

	struct sockaddr_in adr_inet;
	socklen_t len_inet;
	memset(&adr_inet,0,sizeof adr_inet);
    adr_inet.sin_family = AF_INET;
    adr_inet.sin_port = htons(atoi(argv[1]));
    adr_inet.sin_addr.s_addr = INADDR_ANY;

    

	if (adr_inet.sin_addr.s_addr == INADDR_NONE) {
		printf("bad address");
		return 1;
	}

	len_inet = sizeof(struct sockaddr_in);

    // call bind with port number specified as zero to get an unused source port
	if (bind(sock, (struct sockaddr*)&adr_inet, sizeof(struct sockaddr)) == -1)
	{
		printf("bind() failed\n");
		return 1;
	}


    // tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
	{
		printf("setsockopt(IP_HDRINCL, 1) failed\n");
		return 1;
	}

	printf("server listening on port %u\n", adr_inet.sin_port);

	struct sockaddr_in clientAddr;
  	memset(&clientAddr, 0, sizeof(struct sockaddr_in));
  	socklen_t clientAddrLen = sizeof(clientAddr);
    
    unsigned short d_port;
	int received = 0;
    char recvbuf[DATAGRAM_LEN];
    char clientip[INET_ADDRSTRLEN];


	BYTE * data = (BYTE *) malloc(DATAGRAM_LEN);
	do {
		int receive = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &clientAddr, &clientAddrLen);
        memcpy(&d_port, recv + 22, sizeof(d_port));
		if (receive <= 0) {
			printf("receive failed\n");
			return 1;
		}
        memcpy(&d_port, recvbuf + 22, sizeof(d_port));
        // printf("got packet on port: %u : %u\n", d_port, adr_inet.sin_port);
	}
    while (d_port != adr_inet.sin_port);
	inet_ntop(AF_INET, &(clientAddr.sin_addr), clientip, INET_ADDRSTRLEN);
	printf("connected to: %s , bytes : %d\n", clientip, received);
	clientAddr.sin_port = htons(atoi(argv[2]));

    char* packet;
	int packet_len;
    int sent;
	char* request = malloc(1500);
	// // send data

	struct timeval startTime;
	struct timeval currentTime;
	double relativeTime=0;
	
	gettimeofday(&startTime,NULL);
	create_data_packet(&adr_inet, &clientAddr, 33, 45, request, 1440, &packet, &packet_len);
    while (relativeTime <= timeToRun) {
        if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&clientAddr, sizeof(struct sockaddr))) == -1)
        {
            printf("send failed\n");
            return 0;
        }
		usleep(10);
		gettimeofday(&currentTime);
		relativeTime = (currentTime.tv_sec-startTime.tv_sec)+(currentTime.tv_usec-startTime.tv_usec)/1000000.0;
        // else
        // {
        //     printf("successfully sent %d bytes to %u from %u\n", sent, clientAddr.sin_port, adr_inet.sin_port);
        // }
    }
	
	close(sock);
	printf("Server exiting \n");
	return 0;
}