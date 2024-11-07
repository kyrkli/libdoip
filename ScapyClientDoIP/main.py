import time
from scapy.all import *
import socket as socketlib
from scapy.contrib.automotive.doip import *
from scapy.contrib.automotive.uds import UDS, UDS_RDBI

from concurrent.futures import ProcessPoolExecutor

def connect_DoIP_TCP():
    socket = DoIPSocket("127.0.0.1")
    pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
    resp = socket.sr1(pkt, timeout=1)
    print("Received response:", resp)

def connect_DoIP_TLS():
    # Create client-side SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # This disables hostname verification
    context.check_hostname = False
    # This disables server certificate validation entirely.
    context.verify_mode = ssl.CERT_NONE

    # Load client certificate and key required by the server
    context.load_cert_chain(certfile="../ca_keys/client-cert.pem", keyfile="../ca_keys/client-key.pem")

    socket = DoIPSocket(ip="127.0.0.1", tls_port=4433, force_tls=True, context=context)
    pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
    rep = socket.sr1(pkt, timeout=1)
    print(repr(rep))
    socket.outs.unwrap()

def run_script(i):
    print(f"Running script instance {i}")
    connect_DoIP_TLS()

if __name__ == '__main__':
    num_runs = 5  # Number of times to run the script
    connect_DoIP_TLS()
    #with ProcessPoolExecutor() as executor:
    #    futures = [executor.submit(run_script, i) for i in range(num_runs)]

        # Optional: wait for all futures to complete
    #for future in futures:
    #    future.result()  # This will raise exceptions if any occurred in the threads
