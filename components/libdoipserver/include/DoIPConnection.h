#ifndef DOIPCONNECTION_H
#define DOIPCONNECTION_H

#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include "DoIPGenericHeaderHandler.h"
#include "RoutingActivationHandler.h"
#include "VehicleIdentificationHandler.h"
#include "DoIPGenericHeaderHandler.h"
#include "RoutingActivationHandler.h"
#include "DiagnosticMessageHandler.h"
#include "AliveCheckTimer.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

using CloseConnectionCallback = std::function<void()>;

const unsigned long _MaxUdpDataSize = 1520;

class DoIPConnection {

public:
    DoIPConnection(int client_sock, unsigned short logicalGatewayAddress, WOLFSSL* ssl = nullptr):
        client_sock(client_sock), logicalGatewayAddress(logicalGatewayAddress), ssl(ssl){ };

    int receiveTcpOrTlsMessage();
    unsigned long receiveFixedNumberOfBytesFromTcpOrTls(unsigned long payloadLength, unsigned char *receivedData);

    void sendDiagnosticPayload(unsigned short sourceAddress, unsigned char* data, int length);
    bool isSocketActive() { return client_sock != 0; };

    void triggerDisconnection();

    void sendDiagnosticAck(unsigned short sourceAddress, bool ackType, unsigned char ackCode);
    int sendNegativeAck(unsigned char ackCode);

    void setCallback(DiagnosticCallback dc, DiagnosticMessageNotification dmn, CloseConnectionCallback ccb);
    void setGeneralInactivityTime(const uint16_t seconds);

private:

    int client_sock = 0;//client socket for tls or tcp communication

    AliveCheckTimer aliveCheckTimer;
    DiagnosticCallback diag_callback;
    CloseConnectionCallback close_connection;
    DiagnosticMessageNotification notify_application;

    unsigned char* routedClientAddress;
    unsigned short logicalGatewayAddress = 0x0000;

    WOLFSSL *ssl = nullptr;

    void closeSocket();

    int reactOnReceivedTcpMessage(GenericHeaderAction action, unsigned long payloadLength, unsigned char *payload);

    int sendMessage(unsigned char* message, int messageLenght);

    void aliveCheckTimeout();

    int handle_SSL_read_error(int readBytes);
    int handle_SSL_write_error(int sentBytes);
};

#endif /* DOIPCONNECTION_H */
