# raw-tcp

## Issue

As of now, the implementation works on local network but when the sender sends the syn-ack packet, the client doesn't receive it.

## build and run

```bash
gcc sender.c -o sender.out
gcc reciever.c -o receiver.out
```

Run sender(server)

```bash
sudo ./sender.out [listen-port] [duration]
```

Run receiver(mobile/client)

give any filename (i removed logging for debugging purposes)
```bash
sudo ./receiver.out [source-ip] [target-ip] [dest-port] [duration] [filename]
```

The kernel does send a RST packet when it receives something to an
unknown socket destination which is the case with raw sockets. To
prevent this we simply block all outgoing RST packets.

```bash
sudo ./run.sh
```

## Implementation Details

### sender
1. create a raw socket with IPPROTO_TCP so that kernel forwards all incoming TCP packets to this socket.
2. initialize sockaddr_in to start listening from all address
3. optional: call bind (doesn't make a difference for raw socket)
4. explicitly tell the kernel that headers will be passed with data
5. kernel forwards all tcp packets to raw socket so keep receving until we get a packet that has source port
    same as to port on which we are listening. We get source port by reading 22 bytes from the start of recv buffer.

    |  (20 Bytes) | src_port (2 Bytes) dest_port(2 Bytes) ....|
    |   IP        |   TCP                                     |  Payload

6. the first packet received will be a syn packet
7. respond with syn -ack
8. listen for ack packet
9. start sending data wihout rate limiting (for now 1 sec interval for testing and debugging)

### receiver
1. create a raw socket with IPPROTO_TCP so that kernel forwards all incoming TCP packets to this socket.
2. initialize sockaddr_in to start listening from all address
3. optional: call bind (doesn't make a difference for raw socket)
4. explicitly tell the kernel that headers will be passed with data
6. send a syn packet to the server
7. recv syn-ack
8. send an ack packet
9. start listening for data and send acks

