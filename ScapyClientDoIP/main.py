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
    # Create client-side SSL context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # This disables hostname verification
    context.check_hostname = False
    # This disables server certificate validation entirely.
    context.verify_mode = ssl.CERT_NONE

    # Load client certificate and key required by the server
    context.load_cert_chain(certfile="../ca_keys/client-cert.pem", keyfile="../ca_keys/client-key.pem")

    # Establish raw TCP connection
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Wrap the TCP socket with SSL to create a TLS connection
        with context.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
            # Connect to the DoIP server
            ssock.connect((ssock.server_hostname, 4433))

            # Prepare and send the Routing Activation Request (RAR) packet
            rar_packet = DoIP(payload_type=0x0005, source_address=0xe80, activation_type=0x00)  # RAR payload type is 0x0005
            ssock.send(bytes(rar_packet))

            # Prepare and send the DoIP diagnostic message packet
            pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
            #pkt = DoIP(payload_type=0x8002, source_address=0xe80, target_address=0x1000) / Raw(load=b"Custom non-diagnostic message")
            # Send the crafted packet over the TLS connection
            ssock.send(bytes(pkt))
            time.sleep(1)

if __name__ == '__main__':
    connect_DoIP_TLS()