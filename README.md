# CodeAlpha
import socket

# Create a raw socket to listen for incoming packets
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

# Bind the socket to the local machine and any IP address
sniffer.bind(("0.0.0.0", 0))

# Set socket options to include the IP headers
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# On Windows, we need to set the socket in promiscuous mode
# This code is specific to Windows and may vary for other platforms
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Sniff and print raw packets
try:
    while True:
        raw_packet = sniffer.recvfrom(65565)  # Receive packets
        print(raw_packet)  # Print the raw packet data
except KeyboardInterrupt:
    # Disable promiscuous mode when the program is interrupted
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
