#include "DoIPServer.h"

#include<iostream>
#include<iomanip>
#include<thread>
//#include<vector>

using namespace std;

static const unsigned short LOGICAL_ADDRESS = 0x28;

DoIPServer server;
std::vector<unique_ptr<DoIPConnection>> connections;
std::vector<std::thread> doipReceiver;
bool serverActive = false;

/**
 * Is called when the doip library receives a diagnostic message.
 * @param address   logical address of the ecu
 * @param data      message which was received
 * @param length    length of the message
 */
void ReceiveFromLibrary(DoIPConnection* connection, unsigned short target_address, unsigned char* data, int length) {
    cout << "DoIP Message received with target address 0x" << hex << target_address << ": ";
    for(int i = 0; i < length; i++) {
        cout << hex << setw(2) << (int)data[i] << " ";
    }
    cout << endl;

    if(length > 2 && data[0] == 0x22)  {
        cout << "-> Send diagnostic message positive response" << endl;
        unsigned char responseData[] = { 0x62, data[1], data[2], 0x01, 0x02, 0x03, 0x04};
        connection->sendDiagnosticPayload(target_address, responseData, sizeof(responseData));
    } else {
        cout << "-> Send diagnostic message negative response" << endl;
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
bool DiagnosticMessageReceived(unsigned short targetAddress) {
    (void)targetAddress;
    unsigned char ackCode;

    cout << "Received Diagnostic message" << endl;

    //send positiv ack
    ackCode = 0x00;
    cout << "-> Send positive diagnostic message ack" << endl;
    //connection->sendDiagnosticAck(LOGICAL_ADDRESS, true, ackCode);

    return true;
}

/**
 * Closes the connection of the server by ending the listener threads
 */
void CloseConnection() {
    // Make sure this is called as a callback, and clean the connections vector
    cout << "Connection closed" << endl;
    //serverActive = false;
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


void listenTls(){

    server.setupTlsSocket();

    while(true) {
        std::cout << "Waiting for Tls Connection" << std::endl;
        unique_ptr<DoIPConnection> uniConnection = server.waitForTlsConnection();
        DoIPConnection *connection = uniConnection.get();
        connections.push_back(std::move(uniConnection));
        std::cout << "A Tls Connection is found!" << std::endl;
        auto vglambda = [connection](unsigned short address, unsigned char* data, int length)
        {
            ReceiveFromLibrary(connection, address, data, length);
        };
        connection->setCallback(vglambda, DiagnosticMessageReceived, CloseConnection);
        connection->setGeneralInactivityTime(50000);

        while(connection->isSocketActive()) {
            connection->receiveTlsMessage();
        }
        
    }
}

/*
 * Check permantly if tcp message was received
 */
void listenTcp() {

    server.setupTcpSocket();

    while(true) {
        std::cout << "Waiting for Tcp Connection" << std::endl;
        auto uniConnection = server.waitForTcpConnection();
        DoIPConnection *connection = uniConnection.get();
        connections.push_back(std::move(uniConnection));
        std::cout << "A Tcp Connection is found!" << std::endl;
        auto vglambda = [=](unsigned short address, unsigned char* data, int length)
        {
            ReceiveFromLibrary(connection, address, data, length);
        };
        connection->setCallback(vglambda, DiagnosticMessageReceived, CloseConnection);
        connection->setGeneralInactivityTime(50000);

         while(connection->isSocketActive()) {
             connection->receiveTcpMessage();
         }
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
    doipReceiver.push_back(thread(&listenUdp));
    doipReceiver.push_back(thread(&listenTcp));
    doipReceiver.push_back(thread(&listenTls));
    server.sendVehicleAnnouncement();

    doipReceiver.at(0).join();
    doipReceiver.at(1).join();
    doipReceiver.at(2).join();
    return 0;
}
