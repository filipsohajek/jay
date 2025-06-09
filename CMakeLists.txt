cmake_minimum_required(VERSION 3.15)
project(jay)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -g -fsanitize=address")
#set(CMAKE_CXX_FLAGS "-Wall -Wextra -O3 -flto")

add_library(jay src/ip.cpp src/neigh.cpp src/stack.cpp src/sock.cpp src/ipv4.cpp src/ipv6.cpp)
target_include_directories(jay PUBLIC include)

find_package(Catch2 3 REQUIRED)
add_executable(jay_tests test/buf/struct.cpp test/neigh.cpp test/ipv4.cpp test/buf/sbuf.cpp test/util/trie.cpp test/util/smallvec.cpp)
target_include_directories(jay_tests PRIVATE include)
target_link_libraries(jay_tests PRIVATE jay Catch2::Catch2WithMain)

add_executable(jay_experiment src/test.cpp)
target_include_directories(jay_experiment PRIVATE include)
target_link_libraries(jay_experiment PRIVATE jay)
