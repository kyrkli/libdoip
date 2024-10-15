#include "DoIPServer.h"

#include<iostream>
#include<iomanip>
#include<thread>
#include <mutex>

static const unsigned short LOGICAL_ADDRESS = 0x28;

DoIPServer server;
std::vector<std::thread> doipReceiver;
bool serverActive = false;

/**
 * Is called when the doip library receives a diagnostic message.
 * @param address   logical address of the ecu
 * @param data      message which was received
 * @param length    length of the message
 */
void ReceiveFromLibrary(std::unique_ptr<DoIPConnection> &connection, unsigned short target_address, unsigned char* data, int length) {
    std::cout << "DoIP Message received with target address 0x" << std::hex << target_address << ": ";
    for(int i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << (int)data[i] << " ";
    }
    std::cout << std::endl;

    if(length > 2 && data[0] == 0x22)  {
        std::cout << "-> Send diagnostic message positive response" << std::endl;
        unsigned char responseData[] = { 0x62, data[1], data[2], 0x01, 0x02, 0x03, 0x04};
        connection->sendDiagnosticPayload(target_address, responseData, sizeof(responseData));
    } else {
        std::cout << "-> Send diagnostic message negative response" << std::endl;
        unsigned char responseData[] = { 0x7F, data[0], 0x11};
        connection->sendDiagnosticPayload(target_address, responseData, sizeof(responseData));
    }
}

/**
 * Will be called when the doip library receives a diagnostic message.
 * The library notifies the application about the message.
 * Checks if there is a ecu with the logical address
 * @param targetAddress     logical address to the ecu
 * @return                  If a positive or negative ACK should be send to the client
 */
bool DiagnosticMessageReceived(std::unique_ptr<DoIPConnection> &connection, unsigned short targetAddress) {
    (void)targetAddress;
    unsigned char ackCode;

    std::cout << "Received Diagnostic message" << std::endl;

    //send positiv ack
    ackCode = 0x00;
    std::cout << "-> Send positive diagnostic message ack" << std::endl;
    connection->sendDiagnosticAck(LOGICAL_ADDRESS, true, ackCode);

    return true;
}

/**
 * Closes the connection of the server by ending the listener threads
 */
void CloseConnection() {
    std::cout << "Connection closed." << std::endl;
    //--connections_counter;
}

/*
 * Check permantly if udp message was received
 */
void listenUdp() {
    server.setupUdpSocket();
    while(serverActive) {
        server.receiveUdpMessage();
    }
}

void handleClient(std::unique_ptr<DoIPConnection> &&new_conn){        
    //Lambdas for a specific connection
    auto ReceiveFromLibrary_l = [&new_conn](unsigned short address, unsigned char* data, int length)
    {
        ReceiveFromLibrary(new_conn, address, data, length);
    };
    auto DiagnosticMessageReceived_l = [&new_conn](unsigned short targetAddress) -> bool
    {
        return DiagnosticMessageReceived(new_conn, targetAddress);
    };

    new_conn->setCallback(ReceiveFromLibrary_l, DiagnosticMessageReceived_l, CloseConnection);
    new_conn->setGeneralInactivityTime(50000);

    while(new_conn->isSocketActive()) {
        new_conn->receiveTcpOrTlsMessage();
    }

    //Dissconect the client from the application
    new_conn->triggerDisconnection();
}

/*
 * Check permantly if tcp or tls message was received
 */
void listenTcpOrTls(bool isTls = false) {
    server.setupTcpOrTlsSocket(isTls);

    while(true){
        std::unique_ptr<DoIPConnection> uniConnection;
        if(isTls){
            std::cout << "Waiting for Tls Connection" << std::endl;
            uniConnection = server.waitForTlsConnection();
            std::cout << "A Tls Connection is found!" << std::endl;
        }
        else {
            std::cout << "Waiting for Tcp Connection" << std::endl;
            uniConnection = server.waitForTcpConnection();
            std::cout << "A Tcp Connection is found!" << std::endl;
        }
        //++connections_counter;
        std::thread(handleClient, std::move(uniConnection)).detach();
    }
}

void ConfigureDoipServer() {
    // VIN needs to have a fixed length of 17 bytes.
    // Shorter VINs will be padded with '0'
    server.setVIN("FOOBAR");
    server.setLogicalGatewayAddress(LOGICAL_ADDRESS);
    server.setGID(0);
    server.setFAR(0);
    server.setEID(0);

    // doipserver->setA_DoIP_Announce_Num(tempNum);
    // doipserver->setA_DoIP_Announce_Interval(tempInterval);

}

int main() {
    ConfigureDoipServer();
    serverActive = true;
    doipReceiver.push_back(std::thread(&listenUdp));
    doipReceiver.push_back(std::thread(&listenTcpOrTls, false));
    doipReceiver.push_back(std::thread(&listenTcpOrTls, true));
    server.sendVehicleAnnouncement();

    for(auto& th : doipReceiver)
        th.join();

    return 0;
}
