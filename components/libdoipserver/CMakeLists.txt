idf_component_register(
    SRCS "src/DoIPConnection.cpp" "src/DoIPServer.cpp" "src/RoutingActivationHandler.cpp" "src/VehicleIdentificationHandler.cpp"
    INCLUDE_DIRS "include"
    REQUIRES libdoipcommon esp-wolfssl esp_system
    EMBED_TXTFILES  "certs/server-cert.pem"
                    "certs/server-key.pem"
                    "certs/ca-cert.pem"
)
