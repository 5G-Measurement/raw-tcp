# raw-tcp

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

6. get client address from the packet received.
7. construct a raw tcp/ip packet and include data to send as payload.
8. keep sending the data

### receiver