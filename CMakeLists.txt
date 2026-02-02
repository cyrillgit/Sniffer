# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(Sniffer)

set(CMAKE_CXX_STANDARD 11)

project(Sniffer)

set(SOURCE_EXE main.cpp)
set(SOURCE_LIB functions.cpp)

add_library(functions STATIC ${SOURCE_LIB})
add_executable(Sniffer ${SOURCE_EXE})

target_link_libraries(Sniffer functions)