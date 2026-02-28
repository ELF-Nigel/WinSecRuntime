cmake_minimum_required(VERSION 3.20)
project(WinSecRuntime LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(WINSECRUNTIME_HEADER_ONLY "Build header-only" ON)
option(WINSECRUNTIME_BUILD_SHARED "Build shared library" OFF)
option(WINSECRUNTIME_BUILD_EXAMPLES "Build examples" ON)

add_library(WinSecRuntimeHeaders INTERFACE)

target_include_directories(WinSecRuntimeHeaders INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(WinSecRuntimeHeaders INTERFACE
    WINSECRUNTIME_HEADER_ONLY=1
)

if(NOT WINSECRUNTIME_HEADER_ONLY)
    if(WINSECRUNTIME_BUILD_SHARED)
        add_library(WinSecRuntime SHARED src/core.cpp)
    else()
        add_library(WinSecRuntime STATIC src/core.cpp)
    endif()
    target_include_directories(WinSecRuntime PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_definitions(WinSecRuntime PUBLIC WINSECRUNTIME_HEADER_ONLY=0)
endif()

if(WINSECRUNTIME_BUILD_EXAMPLES)
    add_executable(WinSecRuntimeExample examples/full_example.cpp)
    target_include_directories(WinSecRuntimeExample PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    if(WINSECRUNTIME_HEADER_ONLY)
        target_link_libraries(WinSecRuntimeExample PRIVATE WinSecRuntimeHeaders)
    else()
        target_link_libraries(WinSecRuntimeExample PRIVATE WinSecRuntime)
    endif()
endif()
