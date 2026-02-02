cmake_minimum_required(VERSION 3.22.1)
project("titan-verifier-native")

add_library(native-lib SHARED native-lib.cpp audit_engine.cpp)
target_link_libraries(native-lib android log)
