#define DEBUG_WOLFSSL

#include "DoIPServer.h"

#include <signal.h>

#include <wolfssl/wolfcrypt/settings.h>
#ifndef WOLFSSL_ESPIDF
    #error "Problem with wolfSSL user_settings."
    #error "Check components/wolfssl/include"
#endif
#ifndef FP_MAX_BITS
    #error "FP_MAX_BITS not defined"
#endif
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#include <string.h>
//#include <filesystem>
#include <cstdio>

//mac address
extern "C" {
#include "esp_system.h"
#include "esp_mac.h"
#include <stdio.h>
#include "esp_log.h"
}

#define MAC_ADDR_SIZE 6

const char* CERT_FILE_PATH = "../certs/server-cert.pem";
const char* KEY_FILE_PATH = "../certs/server-key.pem";
const char* CA_FILE_PATH = "../certs/ca-cert.pem";

const long get_file_size(const char* path){
    FILE* file = std::fopen(path, "rb");

    if (file != nullptr) {
        std::fseek(file, 0, SEEK_END);
        long fileSize = std::ftell(file);
        std::fclose(file);

        if (fileSize != -1) {
        std::cout << "File size of example.txt is: " << fileSize << " bytes" << std::endl;
        return fileSize;
        } else {
        std::cerr << "Error getting file size." << std::endl;
        }
    } else {
        std::cerr << "Error opening file." << std::endl;
    }
    return 0;
}

/*
//alternatives are fstat or stat approaches
const long get_file_size(const char* path){
    std::filesystem::path filePath = path;
    std::error_code ec;
    //it executes the first command and then checks if ec is 0 or not
    if (const long size = std::filesystem::file_size(filePath, ec); ec){
        std::cout << filePath << " : " << ec.message() << '\n';
        throw std::runtime_error("Failed to get the size of the file.");
    }
    else return size;
}
*/

std::string load_private_key(const char* file_path, long* keySize) {
    *keySize = get_file_size(file_path);
    
    // Open file using ESP-IDF VFS APIs
    int file = open(file_path, O_RDONLY); // Open file in read-only mode
    if (file < 0)
        throw std::runtime_error("Error opening private key file.");
    
    /*
    // Allocate buffer for the file content 
    char* buffer = new char[*keySize + 1](); // +1 for null terminator, default-initialize to zero TODO delete[] after use
    if (!buffer) {
        close(file);
        throw std::runtime_error("Memory allocation failed.");
    }
    */

    // Allocate a buffer with a null terminator
    std::string buffer(*keySize, '\0'); 

    // Read file content into the buffer
    long bytesRead = read(file, &buffer[0], *keySize);
    if (bytesRead != *keySize) {
        close(file);
        throw std::runtime_error("Error reading private key file.");
    }

    // Null-terminate the buffer for safety
    buffer[*keySize] = '\0';

    close(file);
    return buffer;
}

WOLFSSL_CTX *create_context()
{
    WOLFSSL_METHOD *method;
    WOLFSSL_CTX *ctx;
    
    //These are the general-purpose version-flexible SSL/TLS methods.
    //The actual protocol version used will be negotiated to the highest version mutually supported by the client and the server.
    method = wolfSSLv23_server_method();
    if (!method)
        throw std::runtime_error("Failed to create wolfSSL method.");

    //SSL_CTX_new() initializes the list of ciphers, the session cache setting, the callbacks,
    //the keys and certificates and the options to their default values.
    ctx = wolfSSL_CTX_new(method);
    if (!ctx)
        throw std::runtime_error("Failed to create wolfSSL contex.");

    //requirements to the ISO13400-2:2019 TODO setmaxversion?
    if(wolfSSL_CTX_SetMinVersion(ctx, WOLFSSL_TLSV1_2) != SSL_SUCCESS) //TODO clean up in case of the error?
        throw std::runtime_error("Failed to set min version wolfSSL.");

    /*
    //DoIP requirements for cipher suit
    const char* clistTLS1_2 = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
    const char* clistTLS1_3 = "TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
    char clist[400];
    strcat(clist, clistTLS1_2);
    strcat(clist, ":");
    strcat(clist, clistTLS1_3);
    std::cout << "clist:" << clist << std::endl; 
    if(wolfSSL_CTX_set_cipher_list(ctx, clist) != SSL_SUCCESS)
        throw std::runtime_error("Failed to set cipher suite list.");
    
    char ciphers[1000];
    int ret = wolfSSL_get_ciphers(ciphers, (int)sizeof(ciphers));

    if(ret == SSL_SUCCESS)
        printf("get ciphers:%s\n", ciphers);
    else if(ret == BAD_FUNC_ARG)
         printf("BAD_FUNC_ARG\n");
    else if(ret == BUFFER_E)
        printf("BUFFER_E\n");
    */
    return ctx;
}

void configure_context(WOLFSSL_CTX *ctx, bool client_auth)
{
    /* Set the key and cert */
    /*
    if (wolfSSL_CTX_use_certificate_file(ctx, "../ca_keys/server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
        throw std::runtime_error("Failed to use wolfSSL certificate.");
    */
    std::cout << "before wolfSSL_CTX_use_certificate_buffer" << std::endl;
    
    /*
    long key_size = 0; //TODO is call by reference better?
    std::string str = "a";
    */

    extern const unsigned char servercert_start[] asm("_binary_server_cert_pem_start");
    extern const unsigned char servercert_end[]   asm("_binary_server_cert_pem_end");
    long servercert_len = servercert_end - servercert_start;


    int ret = wolfSSL_CTX_use_certificate_buffer(ctx,
            servercert_start,
            servercert_len,
            WOLFSSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        throw std::runtime_error("Error loading private key from buffer.");
    }

    /*
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "../ca_keys/server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS)
        throw std::runtime_error("Failed to use wolfSSL private key.");
    */
    std::cout << "before wolfSSL_CTX_use_PrivateKey_buffer" << std::endl;
    
    extern const unsigned char prvtkey_pem_start[] asm("_binary_server_key_pem_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_server_key_pem_end");
    long prvtkey_pem_len = prvtkey_pem_end - prvtkey_pem_start;


    //str = load_private_key(KEY_FILE_PATH, &key_size);
    ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx,
            prvtkey_pem_start,
            prvtkey_pem_len,
            WOLFSSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        throw std::runtime_error("Error loading private key from buffer.");
    }

    if(client_auth){
        /*
        // Load CA certificate to verify client
        if (wolfSSL_CTX_load_verify_locations(ctx, "../ca_keys/ca-cert.pem", nullptr) != SSL_SUCCESS)  
            throw std::runtime_error("Failed to load SSL ca certificate.");
        */
        std::cout << "before wolfSSL_CTX_load_verify_buffer" << std::endl;
        
        extern const unsigned char cacert_pem_start[] asm("_binary_ca_cert_pem_start");
        extern const unsigned char cacert_pem_end[]   asm("_binary_ca_cert_pem_end");
        long cacert_pem_len = cacert_pem_end - cacert_pem_start;

        ret = wolfSSL_CTX_load_verify_buffer(ctx,
                cacert_pem_start,
                cacert_pem_len,
                WOLFSSL_FILETYPE_PEM);
        if (ret != SSL_SUCCESS) {
            throw std::runtime_error("Error loading private key from buffer.");
        }

        std::cout << "before wolfSSL_CTX_set_verify" << std::endl;
        // Require client to present a certificate
        wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
}

std::unique_ptr<DoIPConnection> DoIPServer::waitForTlsConnection() {
    int ret = 0;
    std::cout << "before accept TLS" << std::endl;
    int client_sock = accept(server_socket_tls, (struct sockaddr*) nullptr, nullptr);
    if (client_sock < 0)
        throw std::runtime_error("Failed to accept tls client.");

    std::cout << "before wolfSSL_new" << std::endl;
    //SSL_new() creates a new SSL structure which is needed to hold the data for a TLS/SSL connection.
    //The new structure inherits the settings of the underlying context ctx: connection method, options, verification settings, timeout settings.
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl)
        throw std::runtime_error("Failed to create a new WOLFSSL object using the wolfSSL_new() function.");

    /*
    //DoIP requirements for cipher suit
    const char *version = wolfSSL_get_version(ssl);

    if(strcmp(version, "TLSv1.2") == 0){
        std::cout << "GET VERSION TLSv1.2" << std::endl;
    } else if(strcmp(version, "TLSv1.3") == 0){
        std::cout << "GET VERSION TLSv1.3" << std::endl;
    } else
        throw std::runtime_error("Used unexpected TLS version.");
    */

    //SSL_set_fd() sets the file descriptor fd as the input/output facility for the TLS/SSL (encrypted) side of ssl.
    //fd will typically be the socket file descriptor of a network connection.
    std::cout << "before wolfSSL_set_fd" << std::endl;
    if(wolfSSL_set_fd(ssl, client_sock) != SSL_SUCCESS)
        throw std::runtime_error("Failed to set wolfSSL file descriptor.");

    //wolfSSL_ERR_print_errors_fp(stderr, wolfSSL_get_error(ssl, ret));
    
    //SSL_accept() waits for a TLS/SSL client to initiate the TLS/SSL handshake.
    //The communication channel must already have been set and assigned to the ssl by setting an underlying BIO.
    std::cout << "before wolfSSL_accept" << std::endl;
    ret = wolfSSL_accept(ssl);
    if (ret != SSL_SUCCESS)
    {
        //wolfSSL_ERR_print_errors_fp(stderr, wolfSSL_get_error(ssl, ret));
        
        //unsigned long err = wolfSSL_ERR_get_error();
        char buffer[80];
        int err = wolfSSL_get_error(ssl, ret);
        wolfSSL_ERR_error_string(err, buffer);
        printf("err = %d, %s\n", err, buffer);

        if (ret != SSL_SUCCESS) {
            char errorString[80];
            wolfSSL_ERR_error_string(err, errorString);
            fprintf(stderr, "WolfSSL error: %s\n", errorString);
        }
        throw std::runtime_error("Failed to accept wolfSSL client.");
    }
    /*
    //debugging
    const char* cipherS = wolfSSL_get_cipher_name(ssl);
    if(cipherS == NULL){
        // There was not a cipher suite matched
    } else {
        // There was a cipher suite matched
        printf("ciphers:%s\n", cipherS);
    }


    version = wolfSSL_get_version(ssl);

    if(strcmp(version, "TLSv1.2") == 0){
        std::cout << "AFTER GET VERSION TLSv1.2" << std::endl;
    } else if(strcmp(version, "TLSv1.3") == 0){
        std::cout << "AFTER GET VERSION TLSv1.3" << std::endl;
    } else
        throw std::runtime_error("Used unexpected TLS version.");
    */
    return std::make_unique<DoIPConnection>(client_sock, LogicalGatewayAddress, ssl);
}

/*
 * Set up a tcp socket, so the socket is ready to accept a connection
 */
void DoIPServer::setupTcpOrTlsSocket(bool is_tls /*=false*/, bool auth_client /*=false*/) {
    int *socket_ptr;
    if(is_tls){
        std::cout << "setup TLS socket" << std::endl;
        wolfSSL_Init();
        socket_ptr = &server_socket_tls;
        ctx = create_context();
        std::cout << "before configure context" << std::endl;
        configure_context(ctx, auth_client);//server-cert.pem and server-key.pem
        std::cout << "after configure context" << std::endl;
    }
    else {
        std::cout << "setup TCP socket" << std::endl;
        socket_ptr = &server_socket_tcp;
    }

    *socket_ptr = socket(AF_INET, SOCK_STREAM, 0);
    if (*socket_ptr < 0) {
        throw std::runtime_error("Unable to create socket");
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    if(is_tls)
        serverAddress.sin_port = htons(_ServerPortTLS);
    else
        serverAddress.sin_port = htons(_ServerPortTcpUdp);

    //binds the socket to the address and port number
    if (bind(*socket_ptr, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
        throw std::runtime_error("Unable to bind");

    //waits till client approach to make connection
    if (listen(*socket_ptr, 5) < 0)
        throw std::runtime_error("Unable to listen");
}

/*
 *  Wait till a client attempts a connection and accepts it
 */
std::unique_ptr<DoIPConnection> DoIPServer::waitForTcpConnection() {
    std::cout << "before accept tcp" << std::endl;
    int client_sock = accept(server_socket_tcp, (struct sockaddr*) nullptr, nullptr);
    std::cout << "after accept tcp" << std::endl;
    if (client_sock < 0)
        throw std::runtime_error("Unable to accept tcp client");

    return std::make_unique<DoIPConnection>(client_sock, LogicalGatewayAddress);
}

void DoIPServer::setupUdpSocket() {

    server_socket_udp = socket(AF_INET, SOCK_DGRAM, 0);

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress.sin_port = htons(_ServerPortTcpUdp);

    if(server_socket_udp < 0)
        std::cout << "Error setting up a udp socket" << std::endl;

    //binds the socket to any IP Address and the Port Number 13400
    bind(server_socket_udp, (struct sockaddr *)&serverAddress, sizeof(serverAddress));

    //setting the IP Address for Multicast
    setMulticastGroup("224.0.0.2");
}

/*
 * Closes the socket for this server
 */
void DoIPServer::closeTlsSocket() {
    CloseSocket(server_socket_tls);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    ctx = nullptr;
}

void DoIPServer::closeTcpSocket() {
    close(server_socket_tcp);
}

void DoIPServer::closeUdpSocket() {
    close(server_socket_udp);
}

/*
 * Receives a udp message and calls reactToReceivedUdpMessage method
 * @return      amount of bytes which were send back to client
 *              or -1 if error occurred
 */
int DoIPServer::receiveUdpMessage(){
    std::cout << "in receiveUdp Message" << std::endl;
    struct sockaddr_in sender;
    socklen_t length = sizeof(serverAddress);
    int readBytes = recvfrom(server_socket_udp, udpData, _MaxUdpDataSize, 0, (struct sockaddr *) &sender, &length);

    int sentBytes = reactToReceivedUdpMessage(readBytes);

    return sentBytes;
}


/*
 * Receives a udp message and determine how to process the message
 * @return      amount of bytes which were send back to client
 *              or -1 if error occurred
 */
int DoIPServer::reactToReceivedUdpMessage(int readedBytes) {

    GenericHeaderAction action = parseGenericHeader(udpData, readedBytes);

    int sendedBytes;
    switch(action.type) {

        case PayloadType::VEHICLEIDENTRESPONSE:{    //server should not send a negative ACK if he receives the sended VehicleIdentificationAnnouncement
            return -1;
        }

        case PayloadType::NEGATIVEACK: {
            //send NACK
            unsigned char* message = createGenericHeader(action.type, _NACKLength);
            message[8] = action.value;
            sendedBytes = sendUdpMessage(message, _GenericHeaderLength + _NACKLength);

            if(action.value == _IncorrectPatternFormatCode ||
                    action.value == _InvalidPayloadLengthCode) {
                return -1;
            } else {
                //discard message when value 0x01, 0x02, 0x03
            }
            return sendedBytes;
        }

        case PayloadType::VEHICLEIDENTREQUEST: {
            unsigned char* message = createVehicleIdentificationResponse(VIN, LogicalGatewayAddress, EID, GID, FurtherActionReq);
            sendedBytes = sendUdpMessage(message, _GenericHeaderLength + _VIResponseLength);

            return sendedBytes;
        }

        default: {
            std::cerr << "not handled payload type occured in receiveUdpMessage()" << std::endl;
            return -1;
        }
    }
    return -1;
}

int DoIPServer::sendUdpMessage(unsigned char* message, int messageLength)  { //sendUdpMessage after receiving a message from the client
    //if the server receives a message from a client, than the response should be send back to the client address and port
    clientAddress.sin_port = serverAddress.sin_port;
    clientAddress.sin_addr.s_addr = serverAddress.sin_addr.s_addr;

    int result = sendto(server_socket_udp, message, messageLength, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));
    return result;
}

void DoIPServer::setEIDdefault(){
    /*
    int fd;

    struct ifreq ifr;
    const char* iface = "ens33"; //eth0
    unsigned char* mac;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy((char*)ifr.ifr_name, (const char*)iface, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    close(fd);

    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
   
    //memcpy(mac, (unsigned char *)ifr.ifr_hwaddr.sa_data, 48);

    for(int i = 0; i < 6; i++)
    {
        EID[i] = mac[i];
    }
    */

    // Retrieve the MAC address for WiFi into EID
    esp_err_t err = esp_read_mac(EID, ESP_MAC_WIFI_STA);

    if (err != ESP_OK) {
        std::cout << "Failed to read MAC address:" << esp_err_to_name(err) << std::endl;

        throw std::runtime_error("Failed to read MAC address");
    }

}

void DoIPServer::setVIN( std::string VINString){

    VIN = VINString;
}

void DoIPServer::setLogicalGatewayAddress(const unsigned short inputLogAdd){
    LogicalGatewayAddress = inputLogAdd;
}

void DoIPServer::setEID(const uint64_t inputEID){
    EID[0] = (inputEID >> 40) &0xFF;
    EID[1] = (inputEID >> 32) &0xFF;
    EID[2] = (inputEID >> 24) &0xFF;
    EID[3] = (inputEID >> 16) &0xFF;
    EID[4] = (inputEID >> 8) &0xFF;
    EID[5] = inputEID  & 0xFF;
}

void DoIPServer::setGID(const uint64_t inputGID){
    GID[0] = (inputGID >> 40) &0xFF;
    GID[1] = (inputGID >> 32) &0xFF;
    GID[2] = (inputGID >> 24) &0xFF;
    GID[3] = (inputGID >> 16) &0xFF;
    GID[4] = (inputGID >> 8) &0xFF;
    GID[5] = inputGID  & 0xFF;
}

void DoIPServer::setFAR(const unsigned int inputFAR){
    FurtherActionReq = inputFAR & 0xFF;
}

void DoIPServer::setA_DoIP_Announce_Num(int Num){
    A_DoIP_Announce_Num = Num;
}

void DoIPServer::setA_DoIP_Announce_Interval(int Interval){
    A_DoIP_Announce_Interval = Interval;
}



void DoIPServer::setMulticastGroup(const char* address) {

    int loop = 1;

    //set Option using the same Port for multiple Sockets
    int setPort = setsockopt(server_socket_udp, SOL_SOCKET, SO_REUSEADDR, &loop, sizeof(loop));

    if(setPort < 0)
    {
        std::cout << "Setting Port Error" << std::endl;
    }


    struct ip_mreq mreq;

    mreq.imr_multiaddr.s_addr = inet_addr(address);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    //set Option to join Multicast Group
    int setGroup = setsockopt(server_socket_udp, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*) &mreq, sizeof(mreq));

    if(setGroup < 0)
    {
        std::cout <<"Setting Address Error" << std::endl;
    }
}


int DoIPServer::sendVehicleAnnouncement() {

    const char* address = "255.255.255.255";

    //setting the destination port for the Announcement to 13401
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port=htons(13401);
    clientAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    int setAddressError = inet_aton(address,&(clientAddress.sin_addr));

    if(setAddressError != 0)
    {
        std::cout <<"Broadcast Address set succesfully"<<std::endl;
    }
    std::cout <<"server socket udp = "<< server_socket_udp << std::endl;
    int socketError = setsockopt(server_socket_udp, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast) );

    if(socketError == 0) {
        std::cout << "Broadcast Option set successfully" << std::endl;
    } else {
        std::cout << "Failed setting broadcast option: " << strerror(errno) << std::endl;
        return -1;
    }

    int sendedmessage = 0;

    unsigned char* message = createVehicleIdentificationResponse(VIN, LogicalGatewayAddress, EID, GID, FurtherActionReq);

    for(int i = 0; i < A_DoIP_Announce_Num; i++)
    {
        sendedmessage = sendto(server_socket_udp, message, _GenericHeaderLength + _VIResponseLength, 0, (struct sockaddr *)&clientAddress, sizeof(clientAddress));
        if(sendedmessage > 0)
        {
            std::cout<<"Sending Vehicle Announcement"<<std::endl;
        }
        else
        {
            std::cout<<"Failed Sending Vehicle Announcement: "<< strerror(errno) << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(A_DoIP_Announce_Interval));

    }
    return sendedmessage;

}
