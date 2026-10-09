add_library(wirebeaver_tunnel STATIC
    tunnel.c
    linux/wireguard.c
)

target_include_directories(wirebeaver_tunnel
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/linux
)

set_target_properties(wirebeaver_tunnel PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO
)

target_compile_options(wirebeaver_tunnel PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)