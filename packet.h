#include <stdio.h> //for printf
#include <string.h> //memset
#include <limits.h>
#include <sys/socket.h>    //for socket ofcourse
#include <sys/types.h>
#include <stdlib.h> //for exit(0);
#include <errno.h> //For errno - the error number
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <linux/filter.h>
#include <stdarg.h>

#define MTU 1440

/* 
    96 bit (12 bytes) pseudo header needed for tcp header checksum calculation 
*/

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

#define FIRST_SYN UINT_MAX - 2
#define REPLY_SYN_ACK UINT_MAX - 1
#define REPLY_ACK UINT_MAX

struct trans_packet_state {
    unsigned int seq;
    unsigned int ack;
};

struct packet_info {
    char dest_ip[128];
    char source_ip[128];
    uint16_t dest_port;
    uint16_t source_port;
    int is_server;
    struct trans_packet_state state;
    int disable_seq_update;
};

int packet_send_sd;
int packet_recv_sd;
char server_bind_ip[128];

void init_packet(struct packet_info* packetinfo);
int send_packet(struct packet_info* packetinfo, char* source_payload, int payloadlen, unsigned int flag);

// 1 for SYN packet, 2 for SYN-ACK packet, 3 for ACK packet, 0 for data packet
void check_packet_recv(struct packet_info* packetinfo, unsigned int type);
unsigned short csum(unsigned short *ptr,int nbytes);
void LOG(const char* message, ...);