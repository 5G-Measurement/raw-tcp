#include "tcp.h"

// first it should connect to the server and then receive packets

int main(int argc,char **argv) {

    if (argc != 6)
	{
		printf("invalid parameters.\n");
		printf("USAGE %s <source-ip> <target-ip> <dest-port> <duration> <filename>\n", argv[0]);
		return 1;
	}

	double timeToRun = strtod(argv[4], NULL);

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
	daddr.sin_port = htons(atoi(argv[3]));
	if (inet_pton(AF_INET, argv[2], &daddr.sin_addr) != 1)
	{
		printf("destination IP configuration failed\n");
		return 1;
	}

	// source IP address configuration
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(atoi(argv[2])); // random client port
	if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1)
	{
		printf("source IP configuration failed\n");
		return 1;
	}

	// // call bind with port number specified as zero to get an unused source port
	// if (bind(sock, (struct sockaddr*)&saddr, sizeof(struct sockaddr)) == -1)
	// {
	// 	printf("bind() failed\n");
	// 	return 1;
	// }

	// // retrieve source port
	// socklen_t addrLen = sizeof(struct sockaddr);
	// if (getsockname(sock, (struct sockaddr*)&saddr, &addrLen) == -1)
	// {
	// 	printf("getsockname() failed\n");
	// 	return 1;
	// }
	printf("selected source port number: %d\n", ntohs(saddr.sin_port));

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

	int sent;
	if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
	{
		printf("sendto() failed\n");
	}
	else
	{
		printf("successfully sent %d bytes SYN!\n", sent);
	}

	// receive SYN-ACK
	char recvbuf[DATAGRAM_LEN];
	int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
	if (received <= 0)
	{
		printf("receive_from() failed\n");
	}
	else
	{
		printf("successfully received %d bytes SYN-ACK!\n", received);
	}

	// read sequence number to acknowledge in next packet
	uint32_t seq_num, ack_num;
	read_seq_and_ack(recvbuf, &seq_num, &ack_num);
	int new_seq_num = seq_num + 1;

	// send ACK
	// previous seq number is used as ack number and vica vera
	create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
	if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
	{
		printf("sendto() failed\n");
	}
	else
	{
		printf("successfully sent %d bytes ACK!\n", sent);
	}

	// receive data

	struct timeval startTime;
	struct timeval currentTime;
	double relativeTime=0;
	int i = 0;
	gettimeofday(&startTime,NULL);
	while (relativeTime <= timeToRun)
	{
		received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
		printf("successfully received %d bytes!\n", received);
		read_seq_and_ack(recvbuf, &seq_num, &ack_num);
		new_seq_num = seq_num + 1;
		create_ack_packet(&saddr, &daddr, ack_num, new_seq_num, &packet, &packet_len);
		if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
		{
			printf("send failed\n");
		}
		else
		{
			printf("successfully sent %d bytes ACK!\n", sent);
		}
		gettimeofday(&currentTime);
		relativeTime = (currentTime.tv_sec-startTime.tv_sec)+(currentTime.tv_usec-startTime.tv_usec)/1000000.0;
	}


	close(sock);
	return 0;
}