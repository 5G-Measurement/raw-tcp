# raw-tcp

## Issue

As of now, the implementation works on local network but on a remote setup, when the sender sends the syn-ack packet, the client doesn't receive it.

## NEW IMPLEMENTATION

To clear all iptable rules to default:
```bash
sudo bash clear.sh
```

**setup**
```bash
make clean
make
```

**receiver**
```bash
sudo iptables -I INPUT -s 192.168.10.12 -p tcp -m tcp --sport 45678 -j DROP
sudo iptables -A INPUT -p tcp -s [SERVER_IP] --sport [SERVER_PORT] -j DROP
sudo ./new-receiver [source-ip] [source-port] [server-ip] [server-port] [duration] [filename]
```

**sender**
```bash
sudo iptables -I INPUT -d 192.168.10.12 -p tcp -m tcp --dport 45678 -j DROP
sudo iptables -A INPUT -p tcp --dport [SERVER_PORT] -j DROP
sudo ./new-sender [listen-ip] [listen-port] [duration]
```


## OLD IMPLEMENTATION

## build and run

```bash
gcc sender.c -o sender.out
gcc receiver.c -o receiver.out
```

Run sender(server)

```bash
sudo ./sender.out [listen-port] [duration]
```

Run receiver(mobile/client)

give any filename (i removed logging for debugging purposes)
```bash
sudo ./receiver.out [source-ip] [target-ip] [src-port] [dest-port] [duration] [filename]
```

The kernel does send a RST packet when it receives something to an
unknown socket destination which is the case with raw sockets. To
prevent this we simply block all outgoing RST packets.

```bash
sudo ./run.sh
```

To reset the rule after the experiment:

```bash
sudo ./stop.sh
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
7. respond with syn-ack
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

