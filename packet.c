#include "packet.h"

// void LOG(const char* message, ...) {
//   time_t now = time(NULL);
//   char timestr[20];
//   strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
//   printf("[%s] ", timestr);
//   va_list argptr;
//   va_start(argptr, message);
//   vfprintf(stdout, message, argptr);
//   va_end(argptr);
//   printf("\n");
//   fflush(stdout);
// }

struct sock_filter code_tcp[] = {
    { 0x30, 0, 0, 0x00000009 },
    { 0x15, 0, 4, 0x00000006 },
    { 0xb1, 0, 0, 0x00000000 },
    { 0x48, 0, 0, 0x00000002 },
    { 0x15, 0, 1, 0x0000fffe },
    { 0x6, 0, 0, 0x0000ffff },
    { 0x6, 0, 0, 0x00000000 },
};

int code_tcp_port_index = 4;

void LOG(const char* message, ...) {
    printf("%s\n", message);
}

void init_bpf(struct packet_info* packetinfo) {

    struct sock_fprog bpf;

    bpf.len = sizeof(code_tcp)/sizeof(code_tcp[0]);
    code_tcp[code_tcp_port_index].k = packetinfo->source_port;
    bpf.filter = code_tcp;
    int dummy;

    int ret=setsockopt(packet_recv_sd, SOL_SOCKET, SO_DETACH_FILTER, &dummy, sizeof(dummy));

    ret = setsockopt(packet_recv_sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
    if (ret != 0) {
        LOG("Error: SO_ATTACH_FILTER");
        exit(-1);
    }
}

void init_packet(struct packet_info* packetinfo) {

    packet_send_sd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    packet_recv_sd = socket(AF_PACKET , SOCK_DGRAM , htons(ETH_P_IP));
    // packet_recv_sd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(packet_send_sd == -1 || packet_recv_sd == -1) {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }

    //IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt (packet_send_sd, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(2);
    }

    (packetinfo->state).seq = 0;
    (packetinfo->state).ack = 1;

    init_bpf(packetinfo);

}


char* pending_stream_buffer = NULL;
int pending_stream_capability = 0;
int pending_stream_len = 0;

void check_packet_recv(struct packet_info* packetinfo, unsigned int type) {
    int saddr_size , size;
    struct sockaddr saddr;
    unsigned short iphdrlen, tcphdrlen;

    struct in_addr from_addr;

    char buffer[MTU];

    saddr_size = sizeof(saddr);

    size = recvfrom(packet_recv_sd, buffer, MTU, 0 ,&saddr , &saddr_size);
    
    if(size < 0 || size < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
        return;
    }

    struct iphdr *iph = (struct iphdr *)buffer;

    if (!(iph->ihl > 0 && iph->ihl < (MTU)/4)) {
        return;
    }

    if (iph->protocol != IPPROTO_TCP) {
        return;
    }

    iphdrlen =iph->ihl*4;
    from_addr.s_addr = iph->saddr;

    struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);

    if (!(tcph->doff > 0 && tcph->doff < (MTU - iphdrlen)/4)) {
        return;
    }

    tcphdrlen = tcph->doff*4;

    if (ntohs(tcph->dest) != packetinfo->source_port) {
        return;
    }

    if (type == 1) { // expecting SYN packet
        struct in_addr to_addr;
        to_addr.s_addr = iph->daddr;
        if (strcmp(server_bind_ip, "0.0.0.0") && strcmp(server_bind_ip, inet_ntoa(to_addr))) {
            return;
        }
        strcpy(packetinfo->source_ip, inet_ntoa(to_addr));

        if (tcph->syn == 1 && tcph->ack == 0 && tcph->psh == 0) {
            // Server replies SYN + ACK
            (packetinfo->state).seq = 1;
            (packetinfo->state).ack = 1;
            strcpy(packetinfo->dest_ip, inet_ntoa(from_addr));
            packetinfo->dest_port = ntohs(tcph->source);
            send_packet(packetinfo, "", 0, REPLY_SYN_ACK);
            return;
        }
    }

    if (type == 2) { // expecting SYN-ACK packet
        if (tcph->syn == 1 && tcph->ack == 1 && tcph->psh == 0) {
            //Client replies first ACK
            (packetinfo->state).seq = 1;
            (packetinfo->state).ack = 1;
            send_packet(packetinfo, "", 0, REPLY_ACK);
            return;
        }
    }

    if (type == 3) { // expecting ACK packet from the receiver
        LOG("Finished processing ACK!");
        return;
    }
    

    if(size < iphdrlen + tcphdrlen + 4) {
        LOG("[packet]size too small, dropping.");
        return;
    }

    // verify TCP checksum

    char pseudo_tcp_buffer[MTU];

    memcpy(pseudo_tcp_buffer, buffer + iphdrlen, size - iphdrlen);

    struct tcphdr* pseudo_tcp_header = (struct tcphdr*)pseudo_tcp_buffer;
    pseudo_tcp_header->check = 0;

    struct pseudo_header psh;

    int payloadlen = size - tcphdrlen - iphdrlen;

    char *pseudogram = malloc(sizeof(struct pseudo_header) + tcphdrlen + payloadlen);

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(tcphdrlen + payloadlen);

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), pseudo_tcp_buffer, size - iphdrlen);

    unsigned short tcp_checksum = csum((short unsigned int*)pseudogram, sizeof(struct pseudo_header) + tcphdrlen + payloadlen);

    free(pseudogram);

    if (tcp_checksum != tcph->check) {
        LOG("[packet]TCP checksum validation failed, dropping.");
        return;
    }

    if (!(packetinfo->disable_seq_update)) {
        (packetinfo->state).ack = ntohl(tcph->seq) + payloadlen;
    }

    char* payload = buffer + iphdrlen + tcphdrlen;
    char* data_payload_buf = payload + 4;
    int data_payload_len = payloadlen - 4;

    unsigned short data_payload_checksum = *((unsigned short*)payload);

    if (csum((unsigned short*)data_payload_buf, data_payload_len) != data_payload_checksum) {
        LOG("[packet]Data checksum validation failed. Dropping.");
        return;
    }

    LOG("Finished processing packet!");
    LOG(payload);
}

int send_packet(struct packet_info* packetinfo, char* source_payload, int source_payloadlen, unsigned int flag) {
    //Datagram to represent the packet
    char datagram[MTU], *data , *pseudogram;

    if (source_payloadlen > MTU - 40 - 4) {
        LOG("[packet]Packet length should not be greater than MTU.");
        return -1;
    }

    char* payload = "";
    int payloadlen = 0;

    if (flag < UINT_MAX - 2) {
        payload = malloc(source_payloadlen + 4);
        unsigned short data_payload_checksum = csum((unsigned short*)source_payload, source_payloadlen);
        memcpy(payload, &data_payload_checksum, 2);
        memset(payload + 2, 0x00, 2);   // 2 reserved bytes
        memcpy(payload + 4, source_payload, source_payloadlen);
        payloadlen = source_payloadlen + 4;
    }

    //zero out the packet buffer
    memset (datagram, 0, MTU);
    //IP header
    struct iphdr *iph = (struct iphdr *) datagram;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    //Data part
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);

    memcpy(data , payload, payloadlen);

    //some address resolution
    sin.sin_family = AF_INET;
    sin.sin_port = htons(packetinfo->dest_port);
    sin.sin_addr.s_addr = inet_addr (packetinfo->dest_ip);

    //Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + payloadlen;
    iph->id = htonl (54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0; //Set to 0 before calculating checksum
    iph->saddr = inet_addr(packetinfo->source_ip);    //Spoof the source ip address
    iph->daddr = sin.sin_addr.s_addr;

    //TCP Header
    tcph->source = htons(packetinfo->source_port);
    tcph->dest = sin.sin_port;
    tcph->seq = htonl((packetinfo->state).seq);
    tcph->ack_seq = htonl((packetinfo->state).ack);
    tcph->doff = 5;  //tcp header size
    tcph->fin=0;
    tcph->syn=0;
    tcph->rst=0;
    tcph->psh=1;
    tcph->ack=1;
    tcph->urg=0;
    tcph->window = htons(12960);
    tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
    tcph->urg_ptr = 0;

    if (flag == FIRST_SYN) {
        tcph->seq = 0;
        tcph->ack = 0;
        tcph->syn = 1;
        tcph->ack_seq = 0;
        tcph->psh=0;
        LOG("[packet]Client sending SYN.");
    }

    if (flag == REPLY_SYN_ACK) {
        tcph->seq = 0;
        tcph->ack_seq = htonl(1);
        tcph->syn = 1;
        tcph->ack = 1;
        tcph->psh=0;
        LOG("[packet]Server replying SYN+ACK.");
    }

    if (flag == REPLY_ACK) {
        tcph->seq = htonl(1);
        tcph->ack_seq = htonl(1);
        tcph->syn = 0;
        tcph->ack = 1;
        tcph->psh=0;
        LOG("[packet]Client replying ACK.");
    }

    //Now the TCP checksum
    psh.source_address = inet_addr(packetinfo->source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + payloadlen );

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + payloadlen;
    pseudogram = malloc(psize);

    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + payloadlen);

    tcph->check = csum( (unsigned short*) pseudogram , psize);

    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    free(pseudogram);
    
    int ret = sendto (packet_send_sd, datagram, iph->tot_len ,  0, (struct sockaddr *) &sin, sizeof (sin));

    // printf("[packet]Sent %d bytes packet.\n", ret);
    if (flag < UINT_MAX - 2) {
        free(payload);
        if (!(packetinfo->disable_seq_update)) {
            ((packetinfo->state).seq) += payloadlen;
        }
    }

    if (ret > 0) {
        return source_payloadlen;
    } else {
        return -1;
    }
}
 
/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((u_char*)&oddbyte)=*(u_char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;

    return(answer);
}
