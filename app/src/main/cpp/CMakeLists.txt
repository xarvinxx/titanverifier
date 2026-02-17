cmake_minimum_required(VERSION 3.22.1)
project("hw-service-native")

add_library(native-lib SHARED native-lib.cpp audit_engine.cpp)
# Phase 9.0: mediandk wird jetzt via dlsym geladen, damit Dobby-Hooks greifen
target_link_libraries(native-lib android log EGL GLESv2 dl)
