#include "packet.h"



int main(int argc, char* argv[]) {

    if (argc != 7)
	{
		printf("invalid parameters.\n");
		printf("USAGE %s <source-ip> <source-port> <server-ip> <server-port> <duration> <filename>\n", argv[0]);
		return 1;
	}

    struct packet_info packetinfo;

    // initialize source and destination addresses
    strcpy(packetinfo.dest_ip, argv[3]);
    packetinfo.dest_port = atoi(argv[4]);
    strcpy(packetinfo.source_ip, argv[1]);
    packetinfo.source_port = atoi(argv[2]);
    packetinfo.is_server = 0;
    packetinfo.disable_seq_update = 0;

    // initialize sender and receiver sockets
    init_packet(&packetinfo);
    LOG("client setup initialized");

    // send a SYN packet
    send_packet(&packetinfo, "", 0, FIRST_SYN);

    // receive SYN-ACK and send ACK
    check_packet_recv(&packetinfo, 2);

    // receive data packet
    check_packet_recv(&packetinfo, 0);
    check_packet_recv(&packetinfo, 0);
    check_packet_recv(&packetinfo, 0);
    
    return 0;
}