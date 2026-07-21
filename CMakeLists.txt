cmake_minimum_required(VERSION 3.24)

project(
    mcp-native-guard
    VERSION 0.1.0
    DESCRIPTION "Native high-performance security boundary for MCP stdio traffic"
    LANGUAGES CXX
)

option(MNG_BUILD_TESTS "Build focused unit tests" ON)
option(MNG_BUILD_BENCHMARKS "Build local microbenchmarks" OFF)
option(MNG_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(MNG_ENABLE_LTO "Enable link-time optimization for release builds" OFF)
option(MNG_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

add_library(mcp_native_guard_core
    src/line_framer.cpp
    src/policy.cpp
    src/proxy_core.cpp
)
add_library(mcp_native_guard::core ALIAS mcp_native_guard_core)

target_compile_features(mcp_native_guard_core PUBLIC cxx_std_20)
target_include_directories(mcp_native_guard_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(MSVC)
    target_compile_options(mcp_native_guard_core PRIVATE /W4 /permissive- /Zc:__cplusplus)
    if(MNG_WARNINGS_AS_ERRORS)
        target_compile_options(mcp_native_guard_core PRIVATE /WX)
    endif()
else()
    target_compile_options(mcp_native_guard_core PRIVATE
        -Wall -Wextra -Wconversion -Wpedantic -Wshadow
    )
    if(MNG_WARNINGS_AS_ERRORS)
        target_compile_options(mcp_native_guard_core PRIVATE -Werror)
    endif()
endif()

if(MNG_ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU" AND NOT WIN32)
        target_compile_options(mcp_native_guard_core PUBLIC
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(mcp_native_guard_core PUBLIC -fsanitize=address,undefined)
    else()
        message(FATAL_ERROR "MNG_ENABLE_SANITIZERS requires Clang or GCC on a non-Windows host")
    endif()
endif()

if(MNG_ENABLE_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
    if(ipo_supported)
        set_property(TARGET mcp_native_guard_core PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
        message(FATAL_ERROR "LTO requested but unavailable: ${ipo_error}")
    endif()
endif()

add_executable(mcp-native-guard src/main.cpp)
target_compile_features(mcp-native-guard PRIVATE cxx_std_20)
target_link_libraries(mcp-native-guard PRIVATE mcp_native_guard::core)
if(MNG_ENABLE_LTO)
    set_property(TARGET mcp-native-guard PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

include(CTest)
if(BUILD_TESTING AND MNG_BUILD_TESTS)
    add_subdirectory(tests)
endif()
if(MNG_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()
