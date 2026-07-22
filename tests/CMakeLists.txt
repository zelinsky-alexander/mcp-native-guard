add_executable(mcp_native_guard_tests test_main.cpp)
target_compile_features(mcp_native_guard_tests PRIVATE cxx_std_20)
target_link_libraries(mcp_native_guard_tests PRIVATE mcp_native_guard::core)
add_test(NAME mcp_native_guard_tests COMMAND mcp_native_guard_tests)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(mcp_native_guard_test_echo_server jsonl_echo_server.cpp)
    target_compile_features(mcp_native_guard_test_echo_server PRIVATE cxx_std_20)

    add_executable(mcp_native_guard_run_integration_tests run_integration_test.cpp)
    target_compile_features(mcp_native_guard_run_integration_tests PRIVATE cxx_std_20)

    add_test(
        NAME mcp_native_guard_run_integration_tests
        COMMAND
            mcp_native_guard_run_integration_tests
            $<TARGET_FILE:mcp-native-guard>
            $<TARGET_FILE:mcp_native_guard_test_echo_server>
            $<TARGET_FILE:mng_test_mcp_server>
    )
endif()
