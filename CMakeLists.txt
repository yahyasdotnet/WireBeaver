cmake_minimum_required(VERSION 3.16)

project(WireBeaverLinuxDaemon LANGUAGES C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "WireBeaverLinuxDaemon is supported on Linux only")
endif()

add_subdirectory(src)