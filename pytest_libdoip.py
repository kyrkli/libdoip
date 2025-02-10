import ssl

import pytest
from pytest_embedded import Dut

from scapy.all import *
from scapy.contrib.automotive.doip import *
from scapy.contrib.automotive.uds import UDS, UDS_RDBI
from scapy.all import fuzz

import threading
import time
import subprocess

import random
from hypothesis import given, settings, strategies as st
from scapy.all import RandInt

ipaddress = ""

certfile_path = "pytest_certs/client-cert.pem"
keyfile_path = "pytest_certs/client-key.pem"
cafile_path = "pytest_certs/ca-cert.pem"

invalid_certfile_path = "pytest_certs/client-cert-invalid.pem"
invalid_keyfile_path = "pytest_certs/client-key-invalid.pem"
invalid_cafile_path = "pytest_certs/ca-cert-invalid.pem"

def connect_DoIP_TCP():
    socket = DoIPSocket(ipaddress)
    pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
    resp = socket.sr1(pkt, timeout=1)
    print("Received response:", resp)

def connect_DoIP_TLS():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Enable unsafe legacy renegotiation (not recommended in production)
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT

    context.check_hostname = False

    # Load client certificate and key required by the server
    context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)

    context.load_verify_locations(cafile=cafile_path)

    socket = DoIPSocket(ip=ipaddress, tls_port=3496, force_tls=True, context=context)
    pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
    pkt.show()
    rep = socket.sr1(pkt, timeout=1)
    print(repr(rep))
    socket.outs.unwrap()

def expect_connect_DoIP_TCP(dut):
    connect_DoIP_TCP()
    dut.expect(r'TCP Layer closed cleanly')

def expect_connect_DoIP_TLS(dut):
    connect_DoIP_TLS()
    dut.expect(r'SSL connection closed cleanly')
    dut.expect(r'TCP Layer closed cleanly')

@pytest.mark.esp32
def test_get_ipaddress(dut) -> None:
    #subprocess.Popen(["idf.py", "monitor"])
    global ipaddress
    ipaddress = dut.expect(r'example_netif_eth ip: (\d+\.\d+\.\d+\.\d+)')[1].decode()
    time.sleep(2)

@pytest.mark.esp32
def test_DoIP_TCP(dut) -> None:
    expect_connect_DoIP_TCP(dut)

@pytest.mark.esp32
def test_DoIP_TLS(dut) -> None:
    expect_connect_DoIP_TLS(dut)

def thread_function(dut, thread_id):
    print(f"Thread {thread_id} is starting.+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    expect_connect_DoIP_TLS(dut)
    time.sleep(5)
    expect_connect_DoIP_TLS(dut)
    print(f"Thread {thread_id} is done----------------------------------------------------------------------")

@pytest.mark.esp32
def test_multithreading(dut) -> None:
    # Create a list to hold the threads
    threads = []

    # Number of threads to create
    num_threads = 3

    #Create and start multiple threads
    for i in range(num_threads):
        thread = threading.Thread(target=thread_function, args=(dut, i))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    print("All threads have finished")

@pytest.mark.esp32
def test_DoIP_TLS_unsupported_version(dut) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.maximum_version = ssl.TLSVersion.TLSv1_1

    # Enable unsafe legacy renegotiation (not recommended in production)
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT

    context.check_hostname = False

    # Load client certificate and key required by the server
    context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)

    context.load_verify_locations(cafile=cafile_path)
    try:
        socket = DoIPSocket(ip=ipaddress, tls_port=3496, force_tls=True, context=context)
    except ssl.SSLError as e:
        if "NO_PROTOCOLS_AVAILABLE" in str(e):
            dut.expect(r'WolfSSL_accept error')
        else:
            pytest.fail("Not expected exception has been thrown.")
    else:
        pytest.fail("This version of the TLS should not be allowed.")

@pytest.mark.esp32
def test_DoIP_TLS_invalid_certificates(dut) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Enable unsafe legacy renegotiation (not recommended in production)
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT

    context.check_hostname = False

    # Load client certificate and key required by the server
    context.load_cert_chain(certfile=invalid_certfile_path, keyfile=invalid_keyfile_path)

    context.load_verify_locations(cafile=invalid_cafile_path)

    try:
        socket = DoIPSocket(ip=ipaddress, tls_port=3496, force_tls=True, context=context)
    except ssl.SSLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            dut.expect(r'WolfSSL_accept error')
        else:
            pytest.fail("Not expected exception has been thrown.")
    else:
        pytest.fail("These certificates should be invalid.")

@pytest.mark.esp32
def test_DoIP_TLS_closed_at_tcp_level(dut) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Enable unsafe legacy renegotiation (not recommended in production)
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT

    context.check_hostname = False

    # Load client certificate and key required by the server
    context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)

    context.load_verify_locations(cafile=cafile_path)

    with DoIPSocket(ip=ipaddress, tls_port=3496, force_tls=True, context=context) as socket:
        pkt = DoIP(payload_type=0x8001, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
        rep = socket.sr1(pkt, timeout=1)
        print(repr(rep))
        #this command should be commented
        #socket.outs.unwrap()
    dut.expect(r'Peer closed underlying transport')
    dut.expect(r'TCP Layer closed cleanly')


@pytest.mark.esp32
def test_DoIP_TLS_invalid_msg_length(dut) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Enable unsafe legacy renegotiation (not recommended in production)
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT

    context.check_hostname = False

    # Load client certificate and key required by the server
    context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)

    context.load_verify_locations(cafile=cafile_path)

    socket = DoIPSocket(ip=ipaddress, tls_port=3496, force_tls=True, context=context)
    pkt = DoIP(payload_type=0x0005, source_address=0xe80, target_address=0x1000) / UDS() / UDS_RDBI(identifiers=[0x1000])
    rep = socket.sr1(pkt, timeout=1)
    print(repr(rep))
    socket.outs.unwrap()

    dut.expect(r'type ROUTINGACTIVATIONREQUEST has not allowed length')
    dut.expect(r'SSL connection closed cleanly')
    dut.expect(r'TCP Layer closed cleanly')


@pytest.mark.esp32
@pytest.mark.parametrize("run", range(5))
def test_DoIP_TLS_fuzz(dut, run) -> None:
    print(f"Run #{run}")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    context.minimum_version = ssl.TLSVersion.TLSv1_2

    # Enable unsafe legacy renegotiation (not recommended in production)
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT

    context.check_hostname = False

    # Load client certificate and key required by the server
    context.load_cert_chain(certfile=certfile_path, keyfile=keyfile_path)
    context.load_verify_locations(cafile=cafile_path)

    socket = DoIPSocket(ip=ipaddress, tls_port=3496, force_tls=True, context=context)
    
    ranges = [(0x0000, 0x0008), (0x4001, 0x4004), (0x8001, 0x8003)]
    min_value, max_value = random.choice(ranges)
    rand_payload_type = random.randint(min_value, max_value)

    pkt = fuzz(DoIP(protocol_version=3, inverse_version=252, payload_type=rand_payload_type, source_address=0xe80)) / UDS() / UDS_RDBI(identifiers=[0x1000])
    pkt.show()
    rep = socket.sr1(pkt, timeout=1)
    print(repr(rep))
    socket.outs.unwrap()

    dut.expect(r'SSL connection closed cleanly')
    dut.expect(r'TCP Layer closed cleanly')