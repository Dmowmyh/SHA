cmake_minimum_required(VERSION 3.5)

project(SHA384)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g --coverage -std=c++14 -fsanitize=address")

set(TEST_SOURCE_FILES SHA384Hash.cpp tests/TestCases.cpp)
file(GLOB SOURCE_FILES "*.cpp")
add_executable(sha384 ${SOURCE_FILES})
add_executable(tests ${TEST_SOURCE_FILES})
