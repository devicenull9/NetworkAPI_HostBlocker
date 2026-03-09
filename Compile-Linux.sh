#!/bin/bash

cmake -D CMAKE_C_COMPILER=gcc -D CMAKE_CXX_COMPILER=g++ -S . -B ./CMake -G Ninja

cmake --build ./CMake
