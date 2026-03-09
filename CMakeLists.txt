cmake_minimum_required(VERSION 3.2.1)

project(NetworkAPI_HostBlocker VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_EXTENSIONS OFF)

set(NETWORKAPI_PATH "/home/user/Documents/NetworkAPI-main")

set(SOURCE_FILES
    "Source/Main.cxx"
)

add_library(NetworkAPI_HostBlocker SHARED ${SOURCE_FILES})

target_include_directories(NetworkAPI_HostBlocker PRIVATE ${NETWORKAPI_PATH}/Include)
target_include_directories(NetworkAPI_HostBlocker PRIVATE ${NETWORKAPI_PATH}/Include/SDK)
