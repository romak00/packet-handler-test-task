cmake_minimum_required(VERSION 3.16)
project(packethandler VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(packetparser STATIC
    src/packet-parser.cpp
    src/packet-parser.h
)

target_include_directories(packetparser PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_executable(packethandler
    src/main.cpp
)

target_link_libraries(packethandler PRIVATE packetparser)

option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()