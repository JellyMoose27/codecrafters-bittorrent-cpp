cmake_minimum_required(VERSION 3.13)

project(bittorrent-starter-cpp)

file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

set(CMAKE_CXX_STANDARD 23) # Enable the C++23 standard

add_executable(bittorrent ${SOURCE_FILES})

find_package(CURL REQUIRED)
target_link_libraries(your_bittorrent.sh PRIVATE CURL::libcurl)