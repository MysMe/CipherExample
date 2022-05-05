cmake_minimum_required(VERSION 3.19)
set (CMAKE_CXX_STANDARD 20)

set(PROJECT_NAME "CipherExample")
project(${PROJECT_NAME})
add_executable(${PROJECT_NAME} "" CipherExample.cpp)
