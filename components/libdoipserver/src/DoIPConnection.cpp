#include "DoIPConnection.h"

#include <iostream>
#include <iomanip>

/**
 * Closes the connection by closing the sockets
 */
void DoIPConnection::aliveCheckTimeout() {
    std::cout << "Alive Check Timeout. Close Connection" << std::endl;
    closeSocket();
    close_connection();
}

/*
 * Closes the socket for this server
 */
void DoIPConnection::closeSocket() {
    if(isSocketActive()){
        //Closing TLS layer
        if(ssl){
            int ret = wolfSSL_shutdown(ssl);

            if (ret == SSL_SHUTDOWN_NOT_DONE) {
                // First shutdown step: client needs to acknowledge shutdown
                std::cout << "Client hasn't acknowledged shutdown, retrying...\n";
                ret = wolfSSL_shutdown(ssl);
            }
            
            if (ret == SSL_SUCCESS)
                std::cout << "SSL connection closed cleanly\n";
            else {
                char errorString[80];
                int err = wolfSSL_get_error(ssl, ret);
                wolfSSL_ERR_error_string(err, errorString);
                fprintf(stderr, "WolfSSL error: %d; %s\n", err, errorString);
                throw std::runtime_error("Failed to call wolfSSL shutdown.");
            }

            wolfSSL_free(ssl);
            ssl = nullptr;
        }
        //Closing TCP layer
        close(client_sock);
        client_sock = 0;
    }
}

int DoIPConnection::handle_SSL_read_error(int readBytes){
    int err = wolfSSL_get_error(ssl, readBytes);
    switch (err)
    {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        //when using non-blocking sockets
        return readBytes;
    case SSL_ERROR_ZERO_RETURN:
        //This caused by a clean (close notify alert) shutdown.
        return readBytes;
    default:
        char errorString[80];
        wolfSSL_ERR_error_string(err, errorString);
        fprintf(stderr, "WolfSSL error: %d; %s\n", err, errorString);
        throw std::runtime_error("Unexpected failure after wolfSSL_read.");
    }
}

/*
 * Receives a message from the client and calls reactToReceivedTcpOrTlsMessage method
 * @return      amount of bytes which were send back to client
 *              or -1 if error occurred
 */
int DoIPConnection::receiveTcpOrTlsMessage() {
    std::cout << "Waiting for DoIP Header..." << std::endl;
    unsigned char genericHeader[_GenericHeaderLength];
    unsigned int readBytes = receiveFixedNumberOfBytesFromTcpOrTls(_GenericHeaderLength, genericHeader);
    if(readBytes == _GenericHeaderLength && !aliveCheckTimer.timeout) {
        std::cout << "Received DoIP Header." << std::endl;
        GenericHeaderAction doipHeaderAction = parseGenericHeader(genericHeader, _GenericHeaderLength);

        unsigned char *payload = nullptr;
        if(doipHeaderAction.payloadLength > 0) {
            std::cout << "Waiting for " << doipHeaderAction.payloadLength << " bytes of payload..." << std::endl;
            payload = new unsigned char[doipHeaderAction.payloadLength];
            unsigned int receivedPayloadBytes = receiveFixedNumberOfBytesFromTcpOrTls(doipHeaderAction.payloadLength, payload);
            if(receivedPayloadBytes != doipHeaderAction.payloadLength) {
                closeSocket();
                return 0;
            }
            std::cout << "DoIP message completely received" << std::endl;
        }

        //if alive check timouts should be possible, reset timer when message received
        if(aliveCheckTimer.active) {
            aliveCheckTimer.resetTimer();
        }

        int sentBytes = reactOnReceivedTcpMessage(doipHeaderAction, doipHeaderAction.payloadLength, payload);
        printf("________________________________________________watermark = %d\n", uxTaskGetStackHighWaterMark(NULL));
        return sentBytes;
    } else {
        closeSocket();
        return 0;
    }
    return -1;

}

/**
 * Receive exactly payloadLength bytes from the TCP or TLS stream and put them into receivedData.
 * The method blocks until receivedData bytes are received or the socket is closed.
 *
 * The parameter receivedData needs to point to a readily allocated array with
 * at least payloadLength items.
 *
 * @return number of bytes received
*/
unsigned long DoIPConnection::receiveFixedNumberOfBytesFromTcpOrTls(unsigned long payloadLength, unsigned char *receivedData) {
    unsigned long payloadPos = 0;
    unsigned long remainingPayload = payloadLength;

    while(remainingPayload > 0) {
        int readBytes = 0;
        if(ssl) 
            readBytes = wolfSSL_read(ssl, &receivedData[payloadPos], remainingPayload);
        else
            readBytes = recv(client_sock, &receivedData[payloadPos], remainingPayload, 0);

        if(readBytes <= 0) {
            if(ssl){
                int ret = handle_SSL_read_error(readBytes);
                if(ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE)
                    continue; //When using non-blocking sockets. The application needs to call wolfSSL_read() again. 
                return ret;
            }
            else
                return payloadPos;
        }
        payloadPos += readBytes;
        remainingPayload -= readBytes;
    }

    return payloadPos;
}

/*
 * Receives a message from the client and determine how to process the message
 * @return      amount of bytes which were send back to client
 *              or -1 if error occurred
 */
int DoIPConnection::reactOnReceivedTcpMessage(GenericHeaderAction action, unsigned long payloadLength, unsigned char *payload) {

    std::cout << "processing DoIP message..." << std::endl;
    int sentBytes;
    switch(action.type) {
        case PayloadType::NEGATIVEACK: {
            //send NACK
            std::cout << "payloadtype NACK" << std::endl;
            sentBytes = sendNegativeAck(action.value);

            if(action.value == _IncorrectPatternFormatCode ||
                    action.value == _InvalidPayloadLengthCode) {
                closeSocket();
                return -1;
            }

            return sentBytes;
        }

        case PayloadType::ROUTINGACTIVATIONREQUEST: {
            std::cout << "payloadtype routing activation request" << std::endl;
            //start routing activation handler with the received message
            unsigned char result = parseRoutingActivation(payload);
            unsigned char clientAddress [2] = {payload[0], payload[1]};

            unsigned char* message = createRoutingActivationResponse(logicalGatewayAddress, clientAddress, result);
            sentBytes = sendMessage(message, _GenericHeaderLength + _ActivationResponseLength);

            if(result == _UnknownSourceAddressCode || result == _UnsupportedRoutingTypeCode) {
                closeSocket();
                return -1;
            } else {
                //Routing Activation Request was successfull, save address of the client
                std::cout << "Routing Activation Request was successfull" << std::endl;
                routedClientAddress = new unsigned char[2];
                routedClientAddress[0] = payload[0];
                routedClientAddress[1] = payload[1];

                //start alive check timer
                if(!aliveCheckTimer.active) {
                    aliveCheckTimer.cb = std::bind(&DoIPConnection::aliveCheckTimeout,this);
                    aliveCheckTimer.startTimer();
                }
            }

            return sentBytes;
        }

        case PayloadType::ALIVECHECKRESPONSE: {
            std::cout << "payloadtype alivecheckresponse" << std::endl;
            return 0;
        }

        case PayloadType::DIAGNOSTICMESSAGE: {
            std::cout << "payloadtype diagnosting message" << std::endl;
            unsigned short target_address = 0;
            target_address |= ((unsigned short)payload[2]) << 8U;
            target_address |= (unsigned short)payload[3];
            bool ack = notify_application(target_address);
            if(ack)
                parseDiagnosticMessage(diag_callback, routedClientAddress, payload, payloadLength);

            break;
        }

        default: {
            std::cerr << "Received message with unhandled payload type: " << action.type << std::endl;
            return -1;
        }
    }
    return -1;
}

void DoIPConnection::triggerDisconnection() {
    std::cout << "Application requested to disconnect Client from Server" << std::endl;
    close_connection();
}

int DoIPConnection::handle_SSL_write_error(int sentBytes){
    int err = wolfSSL_get_error(ssl, sentBytes);
    
    switch (err)
    {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        //When using non-blocking sockets. The application needs to call wolfSSL_write() again.
        return err;
    default:
        //wolfSSL_ERR_print_errors_fp(stderr, err);
        unsigned long err = wolfSSL_ERR_get_error();
        while (err != 0) {
            char errorString[80];
            wolfSSL_ERR_error_string(err, errorString);
            fprintf(stderr, "WolfSSL error: %s\n", errorString);
            err = wolfSSL_ERR_get_error();
        }
        throw std::runtime_error("Unexpected failure after wolfSSL_write.");
    }
}

/**
 * Sends a message back to the connected client
 * @param message           contains generic header and payload specific content
 * @param messageLength     length of the complete message
 * @return                  number of bytes written is returned,
 *                          or -1 if error occurred
 */
int DoIPConnection::sendMessage(unsigned char* message, int messageLength) {
    if(!ssl)
        return write(client_sock, message, messageLength);
    else {
        int sentBytes = wolfSSL_write(ssl, message, messageLength);
        if (sentBytes <= 0) {
                int ret = handle_SSL_write_error(sentBytes);
                if(ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE)
                    return 0;//TODO When using non-blocking sockets. The application needs to call wolfSSL_write() again.
            }
            return sentBytes;
        }

}

/**
 * Sets the time in seconds after which a alive check timeout occurs.
 * Alive check timeouts can be deactivated when setting the seconds to 0
 * @param seconds   time after which alive check timeout occurs
 */
void DoIPConnection::setGeneralInactivityTime(uint16_t seconds) {
    if(seconds > 0) {
        aliveCheckTimer.setTimer(seconds);
    } else {
        aliveCheckTimer.disabled = true;
    }
}

/*
 * Send diagnostic message payload to the client
 * @param sourceAddress   logical source address (i.e. address of this server)
 * @param value     received payload
 * @param length    length of received payload
 */
void DoIPConnection::sendDiagnosticPayload(unsigned short sourceAddress, unsigned char* data, int length) {

    std::cout << "Sending diagnostic data: ";
    for(int i = 0; i < length; i++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (unsigned int)data[i] << " ";
    }
    std::cout << std::endl;

    unsigned char* message = createDiagnosticMessage(sourceAddress, routedClientAddress, data, length);
    sendMessage(message, _GenericHeaderLength + _DiagnosticMessageMinimumLength + length);
}

/*
 * Set the callback function for this doip server instance
 * @dc      Callback which sends the data of a diagnostic message to the application
 * @dmn     Callback which notifies the application of receiving a diagnostic message
 * @ccb     Callback for application function when the library closes the connection
 */
void DoIPConnection::setCallback(DiagnosticCallback dc, DiagnosticMessageNotification dmn, CloseConnectionCallback ccb) {
    diag_callback = dc;
    notify_application = dmn;
    close_connection = ccb;
}

void DoIPConnection::sendDiagnosticAck(unsigned short sourceAddress, bool ackType, unsigned char ackCode) {
    unsigned char data_TA [2] = { routedClientAddress[0], routedClientAddress[1] };

    unsigned char* message = createDiagnosticACK(ackType, sourceAddress, data_TA, ackCode);
    sendMessage(message, _GenericHeaderLength + _DiagnosticPositiveACKLength);
}

/**
 * Prepares a generic header nack and sends it to the client
 * @param ackCode       NACK-Code which will be included in the message
 * @return              amount of bytes sended to the client
 */
int DoIPConnection::sendNegativeAck(unsigned char ackCode) {
    unsigned char* message = createGenericHeader(PayloadType::NEGATIVEACK, _NACKLength);
    message[8] = ackCode;
    int sendedBytes = sendMessage(message, _GenericHeaderLength + _NACKLength);
    return sendedBytes;
}
