#include "DoIPServer.h"

#include<iostream>
#include<iomanip>
#include<thread>
#include <mutex>

static const unsigned short LOGICAL_ADDRESS = 0x28;

DoIPServer server;
std::vector<std::unique_ptr<DoIPConnection>> connections;
std::vector<std::thread> doipReceiver;
std::vector<std::thread> clients;
std::mutex global_mutex;
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
void CloseConnection(std::vector<std::unique_ptr<DoIPConnection>>::iterator &connection_it) {
    // TODO Make sure this is called as a callback, and clean the connections vector
    std::cout << "Connection closed" << std::endl;
    global_mutex.lock();
    connections.erase(connection_it);
    global_mutex.unlock();
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

void handleClient(std::vector<std::unique_ptr<DoIPConnection>>::iterator &new_conn_it){        
    //lambdas for a specific connection TODO comments
    auto receive_lambda = [&new_conn_it](unsigned short address, unsigned char* data, int length)
    {
        ReceiveFromLibrary(*new_conn_it, address, data, length);
    };
    auto DMReceived_lambda = [&new_conn_it](unsigned short targetAddress) -> bool
    {
        return DiagnosticMessageReceived(*new_conn_it, targetAddress);
    };
    auto CloseConnection_l = [&new_conn_it]()
    {
        CloseConnection(new_conn_it);
    };

    (*new_conn_it)->setCallback(receive_lambda, DMReceived_lambda, CloseConnection_l);
    (*new_conn_it)->setGeneralInactivityTime(50000);
    std::cout << "New connection! Size of vector of clients: " << clients.size() << " connections: " << connections.size() << std::endl; 
    //std::this_thread::sleep_for(std::chrono::seconds(10)); // Sleep for 2 seconds

    while((*new_conn_it)->isSocketActive()) {
        (*new_conn_it)->receiveTcpOrTlsMessage();
    }

    (*new_conn_it)->triggerDisconnection();
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
        global_mutex.lock();
        connections.push_back(std::move(uniConnection));
        auto new_conn_it = --connections.end();
        
        clients.push_back(std::thread(handleClient, std::ref(new_conn_it)));
        std::cout << "Hallo........................." << std::endl;
        
        for (auto it = clients.begin(); it != clients.end();)
            if (it->joinable())
                it->detach();
            else
                ++it;
        global_mutex.unlock();
        /*
        // Clean up finished threads
        for (auto it = clients.begin(); it != clients.end();) {
            if (it->joinable()) {
                std::cout << "joinable........................." << std::endl;
                it->join();
                std::cout << "erase........................." << std::endl;
                it = clients.erase(it);  // Erase thread after joining
            } else {
                ++it;
            }
        }
        */
    }
    /*TODO join at the right place*/
    global_mutex.lock();
    for(auto& th : clients)
        th.join();
    global_mutex.unlock();
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
