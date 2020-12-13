#include "packet.h"

int main(int argc, char* argv[]) {

    if (argc != 4)
	{
		printf("invalid parameters.\n");
		printf("USAGE %s <listen-ip> <listen-port> <duration>\n", argv[0]);
		return 1;
	}

    struct packet_info packetinfo;

    // initialize source and destination addresses
    strcpy(server_bind_ip, argv[1]);
    strcpy(packetinfo.source_ip, argv[1]);
    packetinfo.source_port = atoi(argv[2]);
    packetinfo.is_server = 1;
    packetinfo.disable_seq_update = 0;

    // initialize sockets
    init_packet(&packetinfo);
    LOG("server setup initialized");

    // receive SYN packet and send SYN-ACK
    check_packet_recv(&packetinfo, 1);

    // receive ACK packet
    check_packet_recv(&packetinfo, 3);

    // send data packet
    send_packet(&packetinfo, "Hello there 1!", strlen("Hello there 1!"), 0);
    send_packet(&packetinfo, "Hello there 2!", strlen("Hello there 2!"), 0);
    send_packet(&packetinfo, "Hello there 3!", strlen("Hello there 3!"), 0);

    return 0;
}