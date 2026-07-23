add_executable(mcp_native_guard_tests test_main.cpp)
target_compile_features(mcp_native_guard_tests PRIVATE cxx_std_20)
target_link_libraries(mcp_native_guard_tests PRIVATE mcp_native_guard::core)
add_test(NAME mcp_native_guard_tests COMMAND mcp_native_guard_tests)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    add_test(
        NAME mcp_native_guard_audit_summary_tests
        COMMAND ${Python3_EXECUTABLE} -m unittest -v test_audit_health_summary.py
    )
    set_tests_properties(
        mcp_native_guard_audit_summary_tests
        PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif()

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

    add_executable(mcp_native_guard_session_health_integration_tests session_health_integration_test.cpp)
    target_compile_features(mcp_native_guard_session_health_integration_tests PRIVATE cxx_std_20)
    add_test(
        NAME mcp_native_guard_session_health_integration_tests
        COMMAND
            mcp_native_guard_session_health_integration_tests
            $<TARGET_FILE:mcp-native-guard>
            $<TARGET_FILE:mcp_native_guard_test_echo_server>
            $<TARGET_FILE:mng_test_mcp_server>
    )

    add_executable(mcp_native_guard_inspect_integration_tests inspect_integration_test.cpp)
    target_compile_features(mcp_native_guard_inspect_integration_tests PRIVATE cxx_std_20)
    add_test(
        NAME mcp_native_guard_inspect_integration_tests
        COMMAND
            mcp_native_guard_inspect_integration_tests
            $<TARGET_FILE:mcp-native-guard>
            $<TARGET_FILE:mng_test_mcp_server>
    )
endif()
