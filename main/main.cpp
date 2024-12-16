/* Simple HTTP + SSL Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

extern "C" {
#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "esp_eth.h"
#include "protocol_examples_common.h"

#include <esp_https_server.h>
#include "esp_tls.h"
#include "sdkconfig.h"
}
#include "DoIPServer.h"
#include "driver/gpio.h"
#include <iomanip>

static const unsigned short LOGICAL_ADDRESS = 0x28;

DoIPServer server;
std::vector<std::thread> doipReceiver;
bool serverActive = false;
int connections_counter = 0;

/**
 * Is called when the doip library receives a diagnostic message.
 * @param address   logical address of the ecu
 * @param data      message which was received
 * @param length    length of the message
 */
void ReceiveFromLibrary(const std::unique_ptr<DoIPConnection> &connection, const unsigned short target_address, const unsigned char* data, const int length) {
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
bool DiagnosticMessageReceived(const std::unique_ptr<DoIPConnection> &connection, const unsigned short targetAddress) {
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
    --connections_counter;
}

/*
 * Check permantly if udp message was received
 */
void listenUdp() {
    server.setupUdpSocket();
    server.sendVehicleAnnouncement();
    while(true) {
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
void listenTcpOrTls(const bool is_tls = false, const bool client_auth = false) {
    server.setupTcpOrTlsSocket(is_tls, client_auth);
    
    while(true){
        std::unique_ptr<DoIPConnection> uniConnection;
        if(is_tls){
            std::cout << "Waiting for Tls Connection" << std::endl;
            uniConnection = server.waitForTlsConnection();
            std::cout << "A Tls Connection is found!" << std::endl;
        }
        else {
            std::cout << "Waiting for Tcp Connection" << std::endl;
            uniConnection = server.waitForTcpConnection();
            std::cout << "A Tcp Connection is found!" << std::endl;
        }
        ++connections_counter;
        
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

void start_doip_server(void){
    ConfigureDoipServer();
    serverActive = true;
   
    #ifdef _LINUX_
    #ifndef _ESP32_
        doipReceiver.push_back(std::thread(&listenUdp));
        doipReceiver.push_back(std::thread(&listenTcpOrTls, false, false));
        doipReceiver.push_back(std::thread(&listenTcpOrTls, true, true));
    #endif //_ESP32_
    #endif //_LINUX_

    #ifdef _ESP32_
    #ifndef _LINUX_
        int ret_i = 0; /* interim return result */
        
        TaskHandle_t UDP_handle;
        TaskHandle_t TCP_handle;
        TaskHandle_t TLS_handle;

        //Lambdas for converting listeners into the tasks
        auto UDP_listener_task = [](void* arg)
        {
            (void) arg;
            listenUdp();
        };

        auto TCP_listener_task = [](void *arg)
        {
            (void) arg;
            listenTcpOrTls();
        };

        auto TLS_listener_task = [](void *arg)
        {
            (void) arg;
            listenTcpOrTls(true, true);
        };

        ret_i = xTaskCreate(UDP_listener_task, "UDP_listener", 2048, NULL, 8, &UDP_handle);
        if (ret_i != pdPASS)
            throw std::runtime_error("create thread UDP xTask failed");
        
        ret_i = xTaskCreate(TCP_listener_task, "TCP_listener", 2048, NULL, 8, &TCP_handle); //260 bytes overhead
        if (ret_i != pdPASS)
            throw std::runtime_error("create thread TCP xTask failed");

        ret_i = xTaskCreate(TLS_listener_task, "TLS_listener", 4096, NULL, 8, &TLS_handle); //500 bytes overhead
        if (ret_i != pdPASS)
            throw std::runtime_error("create thread TLS xTask failed");
    #endif //_LINUX_
    #endif //_ESP32_
}

void stop_doip_server(){
    serverActive = false;
}


static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    (void) arg;
    if(serverActive)
        stop_doip_server();
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    (void) arg;
    if(!serverActive)
        start_doip_server();
}

extern "C" void app_main(void)
{
    //static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* Register event handlers to start server when Wi-Fi or Ethernet is connected,
     * and stop server when disconnection happens.
     */

#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, NULL));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, NULL));

    // Enable Power to PHY
    const gpio_num_t phy_power_pin = GPIO_NUM_12;
    gpio_config_t phy_power_conf = {0};
    phy_power_conf.mode = GPIO_MODE_OUTPUT;
    phy_power_conf.pin_bit_mask = (1ULL << phy_power_pin);
    ESP_ERROR_CHECK(gpio_config(&phy_power_conf));
    ESP_ERROR_CHECK(gpio_set_level(phy_power_pin, 1));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET
    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());
}