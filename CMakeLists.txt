cmake_minimum_required(VERSION 3.20)
project(WinSecRuntime LANGUAGES CXX)

include(CTest)

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
        target_compile_definitions(WinSecRuntime PUBLIC WINSECRUNTIME_BUILD_SHARED=1)
        target_compile_definitions(WinSecRuntime PRIVATE WINSECRUNTIME_EXPORTS=1)
    else()
        add_library(WinSecRuntime STATIC src/core.cpp)
        target_compile_definitions(WinSecRuntime PUBLIC WINSECRUNTIME_BUILD_SHARED=0)
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
    if(BUILD_TESTING)
        add_test(NAME example_smoke COMMAND WinSecRuntimeExample)
        set_tests_properties(example_smoke PROPERTIES TIMEOUT 15)
        add_executable(heartbeat_lifecycle tests/heartbeat_lifecycle.cpp)
        if(WINSECRUNTIME_HEADER_ONLY)
            target_link_libraries(heartbeat_lifecycle PRIVATE WinSecRuntimeHeaders)
        else()
            target_link_libraries(heartbeat_lifecycle PRIVATE WinSecRuntime)
        endif()
        add_test(NAME heartbeat_lifecycle COMMAND heartbeat_lifecycle)
        set_tests_properties(heartbeat_lifecycle PROPERTIES TIMEOUT 15)
    endif()
endif()
