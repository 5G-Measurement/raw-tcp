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

	printf("server listening on port %u\n", ntohs(adr_inet.sin_port));

	struct sockaddr_in clientAddr;
  	memset(&clientAddr, 0, sizeof(struct sockaddr_in));
  	socklen_t clientAddrLen = sizeof(clientAddr);
    
    unsigned short d_port, s_port;
	int received = 0;
    char recvbuf[DATAGRAM_LEN];
    char clientip[INET_ADDRSTRLEN];

	// Receive SYN Packet
	BYTE * data = (BYTE *) malloc(DATAGRAM_LEN);
	do {
		int receive = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &clientAddr, &clientAddrLen);
		if (receive <= 0) {
			printf("receive failed\n");
			return 1;
		}
        memcpy(&d_port, recvbuf + 22, sizeof(d_port));
		memcpy(&s_port, recvbuf + 20, sizeof(s_port));
        // printf("got packet on port: %u : %u\n", d_port, adr_inet.sin_port);
	}
    while (d_port != adr_inet.sin_port);
	inet_ntop(AF_INET, &(clientAddr.sin_addr), clientip, INET_ADDRSTRLEN);
	printf("connected to: %s , port : %d\n", clientip, ntohs(s_port));
	clientAddr.sin_port = s_port;

	char* packet;
	int packet_len;
    int sent;

	// read sequence number to acknowledge in next packet
	uint32_t seq_num, ack_num;
	read_seq_and_ack(recvbuf, &seq_num, &ack_num);
	int new_seq_num = seq_num + 1;

	// Send SYN-ACK Packet
	create_syn_ack_packet(&adr_inet, &clientAddr, new_seq_num, &packet, &packet_len);
	if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&clientAddr, sizeof(struct sockaddr))) == -1)
	{
		printf("sendto() failed\n");
	}
	else
	{
		printf("successfully sent %d bytes SYN ACK to port %s \n", ntohs(clientAddr.sin_port));
	}

	// receive ACK packet
	received = receive_from(sock, recvbuf, sizeof(recvbuf), &clientAddr);
	if (received <= 0)
	{
		printf("receive_from() failed\n");
	}
	else
	{
		printf("successfully received %d bytes SYN-ACK!\n", received);
	}

	read_seq_and_ack(recvbuf, &seq_num, &ack_num);
	new_seq_num = seq_num + 1;
    

	struct timeval startTime;
	struct timeval currentTime;
	double relativeTime=0;
	int i = 0;
	char request[] = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
	gettimeofday(&startTime,NULL);
    while (relativeTime <= timeToRun) {
		// send data
	
		create_data_packet(&adr_inet, &clientAddr, ack_num, new_seq_num, request, sizeof(request) - 1/sizeof(char), &packet, &packet_len);
		if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&clientAddr, sizeof(struct sockaddr))) == -1)
		{
			printf("send failed\n");
		}
		else
		{
			printf("successfully sent %d bytes PSH to port %s\n", sent, ntohs(clientAddr.sin_port));
		}
		
		gettimeofday(&currentTime);
		relativeTime = (currentTime.tv_sec-startTime.tv_sec)+(currentTime.tv_usec-startTime.tv_usec)/1000000.0;
		i++;
		free(packet);

		// receive ACK packet
		received = receive_from(sock, recvbuf, sizeof(recvbuf), &clientAddr);
		if (received <= 0)
		{
			printf("receive_from() failed\n");
		}
		else
		{
			printf("successfully received %d bytes SYN-ACK!\n", received);
		}

		read_seq_and_ack(recvbuf, &seq_num, &ack_num);
		new_seq_num = seq_num + 1;
        // else
        // {
        //     printf("successfully sent %d bytes to %u from %u\n", sent, clientAddr.sin_port, adr_inet.sin_port);
        // }
		sleep(1);
    }
	
	close(sock);
	printf("Server exiting \n");
	return 0;
}