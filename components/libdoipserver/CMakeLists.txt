idf_component_register(
    SRCS "src/DoIPConnection.cpp" "src/DoIPServer.cpp" "src/RoutingActivationHandler.cpp" "src/VehicleIdentificationHandler.cpp"
    INCLUDE_DIRS "include"
    REQUIRES libdoipcommon esp-wolfssl
)

target_compile_options(${COMPONENT_LIB} PRIVATE -fexceptions)
