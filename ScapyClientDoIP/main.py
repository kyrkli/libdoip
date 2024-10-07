# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket
import ssl
from scapy.all import *
from scapy.contrib.automotive.doip import *
from scapy.contrib.automotive.uds import UDS, UDS_RDBI

def connect_DoIP_TCP():
    socket = DoIPSocket("127.0.0.1")
    pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
    resp = socket.sr1(pkt, timeout=1)
    print("Received response:", resp)


def connect_DoIP_TLS():
    # Establish raw TCP connection
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Create client-side SSL context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Disable server certificate verification (Not secure for production)
    # This disables hostname verification.
    context.check_hostname = False
    # This disables server certificate validation entirely.
    context.verify_mode = ssl.CERT_NONE

    # Optional: Load client certificate and key if required by the server
    context.load_cert_chain(certfile="../ca_keys/client-cert.pem", keyfile="../ca_keys/client-key.pem")

    # Wrap the TCP socket with SSL to create a TLS connection
    tls_socket = context.wrap_socket(tcp_socket, server_hostname="127.0.0.1")  # For client-side

    # Connect to the DoIP server (replace '127.0.0.1' with the server IP and port)
    tls_socket.connect(("127.0.0.1", 4433))

    # Send DoIP packet over the TLS connection
    pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(
        identifiers=[0x1000])

    # Send the crafted packet over the TLS connection
    tls_socket.send(bytes(pkt))

    # Receive response (if needed)
    response = tls_socket.recv(1024)
    print("Received response:", response)

    # Close the connection
    tls_socket.close()

if __name__ == '__main__':
    connect_DoIP_TLS()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
