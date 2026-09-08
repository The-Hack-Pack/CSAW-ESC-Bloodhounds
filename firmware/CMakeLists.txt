# Project-level ESP-IDF build file. Mirrors host_twin/ so a finding on the
# twin can be re-confirmed on real Xtensa hardware (README Phase C).
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esc26_testbed)
