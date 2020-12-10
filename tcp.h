#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define DATAGRAM_LEN 4096
#define OPT_SIZE 20
#define OPT_SIZE_SYN 12
#define OPT_SIZE_SYN_ACK 12
typedef unsigned char BYTE;
#define BUFFER_SIZE 50000

// pseudo header needed for tcp header checksum calculation
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

unsigned short checksum(const char *buf, unsigned size)
{
	unsigned sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}

void create_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** out_packet, int* out_packet_len)
{
	// datagram to represent the packet
	char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)datagram;
	struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
	struct pseudo_header psh;

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE_SYN;
	iph->id = htonl(rand() % 65535); // id of this packet
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // correct calculation follows later
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;

	// TCP header configuration
	tcph->source = src->sin_port;
	tcph->dest = dst->sin_port;
	tcph->seq = htonl(rand() % 4294967295);
	tcph->ack_seq = htonl(0);
	tcph->doff = (sizeof(struct tcphdr) + OPT_SIZE_SYN) / 4; // tcp header size
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->check = 0; // correct calculation follows later
	tcph->window = htons(29200); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = sizeof(struct tcphdr) + OPT_SIZE_SYN;
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE_SYN;
	// fill pseudo packet
	char* pseudogram = malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE_SYN);

	// 4-byte MSS + 1-byte NOP + 3-byte window scaling + 1-byte NOP + 1-byte NOP + 2-byte SACK permission (12 bytes in total)
	// TCP options are only set in the SYN packet
	// ---- set mss ----
	datagram[40] = 0x02;
	datagram[41] = 0x04;
	int16_t mss = htons(1460); // mss value
	memcpy(datagram + 42, &mss, sizeof(int16_t)); // 42 and 43
	// ---- NOP -----
	datagram[44] = 0x01;
	// ---- window-scaling -----
	datagram[45] = 0x03;
	datagram[46] = 0x03;
	datagram[47] = 0x08;
	// ---- 2 NOPs ----
	datagram[48] = 0x01;
	datagram[49] = 0x01;
	// ---- enable SACK ----
	datagram[50] = 0x04;
	datagram[51] = 0x02;
	// do the same for the pseudo header
	pseudogram[32] = 0x02;
	pseudogram[33] = 0x04;
	memcpy(pseudogram + 34, &mss, sizeof(int16_t));
	pseudogram[36] = 0x01;
	pseudogram[37] = 0x03;
	pseudogram[38] = 0x03;
	pseudogram[39] = 0x08;
	pseudogram[40] = 0x01;
	pseudogram[41] = 0x01;
	pseudogram[42] = 0x04;
	pseudogram[43] = 0x02;

	tcph->check = checksum((const char*)pseudogram, psize);
	iph->check = checksum((const char*)datagram, iph->tot_len);

	*out_packet = datagram;
	*out_packet_len = iph->tot_len;
	free(pseudogram);
}

void create_syn_ack_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t ack_seq, char** out_packet, int* out_packet_len) {
	// datagram to represent the packet
	char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)datagram;
	struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
	struct pseudo_header psh;

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE_SYN_ACK;
	iph->id = htonl(rand() % 65535); // id of this packet
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // correct calculation follows later
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;

	// TCP header configuration
	tcph->source = src->sin_port;
	tcph->dest = dst->sin_port;
	tcph->seq = htonl(rand() % 4294967295);
	tcph->ack_seq = htonl(ack_seq);
	tcph->doff = (sizeof(struct tcphdr) + OPT_SIZE_SYN_ACK) / 4; // tcp header size
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->check = 0; // correct calculation follows later
	tcph->window = htons(29200); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE_SYN_ACK);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE_SYN_ACK;
	// fill pseudo packet
	char* pseudogram = malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE_SYN_ACK);

	// ---- set mss ----
	datagram[40] = 0x02;
	datagram[41] = 0x04;
	int16_t mss = htons(1460); // mss value
	memcpy(datagram + 42, &mss, sizeof(int16_t)); // 42 and 43
	// ---- 2 NOPs ----
	datagram[44] = 0x01;
	datagram[45] = 0x01;
	// ---- enable SACK ----
	datagram[46] = 0x04;
	datagram[47] = 0x02;
	// ----- NOP ------
	datagram[48] = 0x01;
	// ---- window-scaling -----
	datagram[49] = 0x03;
	datagram[50] = 0x03;
	datagram[51] = 0x07;
	
	// do the same for the pseudo header
	pseudogram[32] = 0x02;
	pseudogram[33] = 0x04;
	memcpy(pseudogram + 34, &mss, sizeof(int16_t));
	pseudogram[36] = 0x01;
	pseudogram[37] = 0x01;
	pseudogram[38] = 0x04;
	pseudogram[39] = 0x02;
	pseudogram[40] = 0x01;
	pseudogram[41] = 0x03;
	pseudogram[42] = 0x03;
	pseudogram[43] = 0x07;

	tcph->check = checksum((const char*)pseudogram, psize);
	iph->check = checksum((const char*)datagram, iph->tot_len);

	*out_packet = datagram;
	*out_packet_len = iph->tot_len;
	free(pseudogram);
}


void create_ack_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char** out_packet, int* out_packet_len)
{
	// datagram to represent the packet
	char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)datagram;
	struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
	struct pseudo_header psh;

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	iph->id = htonl(rand() % 65535); // id of this packet
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // correct calculation follows later
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;

	// TCP header configuration
	tcph->source = src->sin_port;
	tcph->dest = dst->sin_port;
	tcph->seq = htonl(seq);
	tcph->ack_seq = htonl(ack_seq);
	tcph->doff = 10; // tcp header size
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->check = 0; // correct calculation follows later
	tcph->window = htons(5840); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
	// fill pseudo packet
	char* pseudogram = malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

	tcph->check = checksum((const char*)pseudogram, psize);
	iph->check = checksum((const char*)datagram, iph->tot_len);

	*out_packet = datagram;
	*out_packet_len = iph->tot_len;
	free(pseudogram);
}


void create_data_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char* data, int data_len, char** out_packet, int* out_packet_len)
{
	// datagram to represent the packet
	char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)datagram;
	struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
	struct pseudo_header psh;

	// set payload
	char* payload = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	memcpy(payload, data, data_len);

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
	iph->id = htonl(rand() % 65535); // id of this packet
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // correct calculation follows later
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;

	// TCP header configuration
	tcph->source = src->sin_port;
	tcph->dest = dst->sin_port;
	tcph->seq = htonl(seq);
	tcph->ack_seq = htonl(ack_seq);
	tcph->doff = 10; // tcp header size
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 0;
	tcph->psh = 1;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->check = 0; // correct calculation follows later
	tcph->window = htons(5840); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + data_len);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
	// fill pseudo packet
	char* pseudogram = malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE + data_len);

	tcph->check = checksum((const char*)pseudogram, psize);
	iph->check = checksum((const char*)datagram, iph->tot_len);

	*out_packet = datagram;
	*out_packet_len = iph->tot_len;
	free(pseudogram);
}

void read_seq_and_ack(const char* packet, uint32_t* seq, uint32_t* ack)
{
	// read sequence number
	uint32_t seq_num;
	memcpy(&seq_num, packet + 24, 4);
	// read acknowledgement number
	uint32_t ack_num;
	memcpy(&ack_num, packet + 28, 4);
	// convert network to host byte order
	*seq = ntohl(seq_num);
	*ack = ntohl(ack_num);
	printf("sequence number: %lu\n", (unsigned long)*seq);
	printf("acknowledgement number: %lu\n", (unsigned long)*ack);

}

int receive_from(int sock, char* buffer, size_t buffer_length, struct sockaddr_in *dst)
{
	unsigned short dst_port;
	int received;
	do
	{
		received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
		if (received < 0)
			break;
		memcpy(&dst_port, buffer + 22, sizeof(dst_port));
	}
	while (dst_port != dst->sin_port);
	// printf("received bytes: %d\n", received);
	// printf("destination port: %d\n", ntohs(dst->sin_port));
	return received;
}
